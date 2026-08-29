import { useCallback, useEffect, useMemo, useState } from 'preact/hooks';
import { ArrowLeft, Building2, FolderPlus, KeyRound, Plus, RefreshCw, ShieldCheck, Trash2, UserPlus, X } from 'lucide-preact';
import type { Profile } from '@/lib/types';
import type { AuthedFetch } from '@/lib/api/shared';
import {
  listOrganizations,
  createOrganization,
  listOrganizationMembers,
  listOrganizationInvitations,
  inviteOrganizationMember,
  updateOrganizationMember,
  removeOrganizationMember,
  revokeOrganizationInvitation,
  listCollections,
  createCollection,
  updateCollection,
  deleteCollection,
  getMemberPublicKeyByEmail,
  listMyInvitations,
  acceptMyInvitation,
  declineMyInvitation,
  getMemberPublicKey,
  getSsoConfig,
  saveSsoConfig,
  getScimConfig,
  saveScimConfig,
  type OrganizationSummary,
  type OrganizationMemberItem,
  type MyInvitationItem,
  type OrganizationInvitationItem,
  type CollectionItem,
  type SsoConfigItem,
  type ScimConfigItem,
} from '@/lib/api/organizations';
import { createOrgKeySet, deriveOrgKeyBytes, encryptOrgKeyForMember } from '@/lib/org-keys';
import { t } from '@/lib/i18n';

interface AdminOrganizationsPageProps {
  authedFetch: AuthedFetch;
  profile: Profile | null;
  sessionSymEncKey?: string;
  sessionSymMacKey?: string;
  onNotify: (type: 'success' | 'error' | 'warning', text: string) => void;
}

const ORG_ROLE_OPTIONS = ['owner', 'admin', 'manager', 'member'];

function canManage(org: OrganizationSummary): boolean {
  return org.role === 'owner' || org.role === 'admin' || org.role === 'manager';
}

export default function AdminOrganizationsPage(props: AdminOrganizationsPageProps) {
  const { authedFetch, profile, sessionSymEncKey, sessionSymMacKey, onNotify } = props;
  const [orgs, setOrgs] = useState<OrganizationSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedOrgId, setSelectedOrgId] = useState<string | null>(null);
  const [showCreateOrg, setShowCreateOrg] = useState(false);
  const [newOrgName, setNewOrgName] = useState('');
  const [newOrgIdentifier, setNewOrgIdentifier] = useState('');
  const [creatingOrg, setCreatingOrg] = useState(false);

  const [members, setMembers] = useState<OrganizationMemberItem[]>([]);
  const [sharingKeyFor, setSharingKeyFor] = useState<string | null>(null);
  const [myInvitations, setMyInvitations] = useState<MyInvitationItem[]>([]);
  const [invitationBusy, setInvitationBusy] = useState<string | null>(null);
  const [invitations, setInvitations] = useState<OrganizationInvitationItem[]>([]);
  const [collections, setCollections] = useState<CollectionItem[]>([]);
  const [ssoConfig, setSsoConfig] = useState<SsoConfigItem | null>(null);
  const [scimConfig, setScimConfig] = useState<ScimConfigItem | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const [inviteEmail, setInviteEmail] = useState('');
  const [inviteRole, setInviteRole] = useState('member');
  const [inviting, setInviting] = useState(false);
  const [newCollectionName, setNewCollectionName] = useState('');
  const [creatingCollection, setCreatingCollection] = useState(false);

  const selectedOrg = useMemo(() => orgs.find((org) => org.id === selectedOrgId) || null, [orgs, selectedOrgId]);
  const manageEnabled = !!selectedOrg && canManage(selectedOrg);

  const refreshOrgs = useCallback(async () => {
    try {
      const [data, invitations] = await Promise.all([
        listOrganizations(authedFetch),
        listMyInvitations(authedFetch).catch(() => [] as MyInvitationItem[]),
      ]);
      setOrgs(data);
      setMyInvitations(invitations);
    } catch (error) {
      onNotify('error', error instanceof Error ? error.message : t('txt_orgs_load_failed'));
    } finally {
      setLoading(false);
    }
  }, [authedFetch, onNotify]);

  // An invitation is only actionable by the person it was addressed to, so this
  // is the one place it can be accepted or turned down.
  async function handleInvitationResponse(invitation: MyInvitationItem, accept: boolean) {
    setInvitationBusy(invitation.id);
    try {
      if (accept) {
        await acceptMyInvitation(authedFetch, invitation.token);
        onNotify('success', t('txt_org_invitation_accepted'));
      } else {
        await declineMyInvitation(authedFetch, invitation.token);
        onNotify('success', t('txt_org_invitation_declined'));
      }
      await refreshOrgs();
    } catch (error) {
      onNotify('error', error instanceof Error ? error.message : t('txt_org_invitation_action_failed'));
    } finally {
      setInvitationBusy(null);
    }
  }

  useEffect(() => {
    void refreshOrgs();
  }, [refreshOrgs]);

  const refreshDetail = useCallback(async (orgId: string) => {
    setDetailLoading(true);
    try {
      const [membersData, invitationsData, collectionsData, ssoData, scimData] = await Promise.all([
        listOrganizationMembers(authedFetch, orgId),
        listOrganizationInvitations(authedFetch, orgId).catch(() => []),
        listCollections(authedFetch, orgId),
        getSsoConfig(authedFetch, orgId).catch(() => null),
        getScimConfig(authedFetch, orgId).catch(() => null),
      ]);
      setMembers(membersData);
      setInvitations(invitationsData);
      setCollections(collectionsData);
      setSsoConfig(ssoData);
      setScimConfig(scimData);
    } catch (error) {
      onNotify('error', error instanceof Error ? error.message : t('txt_org_detail_load_failed'));
    } finally {
      setDetailLoading(false);
    }
  }, [authedFetch, onNotify]);

  const selectOrg = useCallback((orgId: string) => {
    setSelectedOrgId(orgId);
    if (orgId) void refreshDetail(orgId);
  }, [refreshDetail]);

  async function handleCreateOrg() {
    const name = newOrgName.trim();
    if (!name) {
      onNotify('error', t('txt_org_name_required'));
      return;
    }
    if (!profile?.publicKey) {
      onNotify('error', t('txt_org_create_requires_rsa_key'));
      return;
    }
    setCreatingOrg(true);
    try {
      const keySet = await createOrgKeySet(profile.publicKey);
      const org = await createOrganization(authedFetch, {
        name,
        identifier: newOrgIdentifier.trim() || undefined,
        publicKey: keySet.publicKey,
        privateKey: keySet.privateKey,
        encryptedOrgKey: keySet.encryptedOrgKey,
      });
      setNewOrgName('');
      setNewOrgIdentifier('');
      setShowCreateOrg(false);
      onNotify('success', t('txt_org_created'));
      await refreshOrgs();
      selectOrg(org.id);
    } catch (error) {
      onNotify('error', error instanceof Error ? error.message : t('txt_org_create_failed'));
    } finally {
      setCreatingOrg(false);
    }
  }

  async function handleInvite() {
    if (!selectedOrg) return;
    const email = inviteEmail.trim();
    if (!email) {
      onNotify('error', t('txt_org_invite_email_required'));
      return;
    }
    setInviting(true);
    try {
      let encryptedOrgKey: string | undefined;
      const orgKeyBytes = profile
        ? await deriveOrgKeyBytes(profile, sessionSymEncKey || '', sessionSymMacKey || '', selectedOrg.id)
        : null;
      if (orgKeyBytes) {
        try {
          const target = await getMemberPublicKeyByEmail(authedFetch, selectedOrg.id, email);
          encryptedOrgKey = await encryptOrgKeyForMember(orgKeyBytes, target.publicKey);
        } catch {
          // Member public key unavailable (no account yet); invite without a key.
        }
      }
      const body: Record<string, unknown> = { email, role: inviteRole, collections: [] };
      if (encryptedOrgKey) body.encryptedOrgKey = encryptedOrgKey;
      await inviteOrganizationMember(authedFetch, selectedOrg.id, body);
      setInviteEmail('');
      setInviteRole('member');
      onNotify('success', t('txt_org_member_invited'));
      await refreshDetail(selectedOrg.id);
    } catch (error) {
      onNotify('error', error instanceof Error ? error.message : t('txt_org_invite_failed'));
    } finally {
      setInviting(false);
    }
  }

  // Members who joined through an invitation or SSO have no copy of the org key
  // yet, so they cannot decrypt anything until an admin re-encrypts it for them.
  async function handleShareKey(member: OrganizationMemberItem) {
    if (!selectedOrg || !profile) return;
    setSharingKeyFor(member.id);
    try {
      const orgKeyBytes = await deriveOrgKeyBytes(profile, sessionSymEncKey || '', sessionSymMacKey || '', selectedOrg.id);
      if (!orgKeyBytes) {
        onNotify('error', t('txt_org_key_unavailable'));
        return;
      }
      const target = await getMemberPublicKey(authedFetch, selectedOrg.id, member.id);
      const encryptedOrgKey = await encryptOrgKeyForMember(orgKeyBytes, target.publicKey);
      await updateOrganizationMember(authedFetch, selectedOrg.id, member.id, { encryptedOrgKey });
      onNotify('success', t('txt_org_key_shared'));
      await refreshDetail(selectedOrg.id);
    } catch (error) {
      onNotify('error', error instanceof Error ? error.message : t('txt_org_key_share_failed'));
    } finally {
      setSharingKeyFor(null);
    }
  }

  async function handleRemoveMember(memberId: string) {
    if (!selectedOrg) return;
    try {
      await removeOrganizationMember(authedFetch, selectedOrg.id, memberId);
      onNotify('success', t('txt_org_member_removed'));
      await refreshDetail(selectedOrg.id);
    } catch (error) {
      onNotify('error', error instanceof Error ? error.message : t('txt_org_member_remove_failed'));
    }
  }

  async function handleChangeMemberRole(member: OrganizationMemberItem, role: string) {
    if (!selectedOrg) return;
    try {
      await updateOrganizationMember(authedFetch, selectedOrg.id, member.id, { role });
      onNotify('success', t('txt_org_member_updated'));
      await refreshDetail(selectedOrg.id);
    } catch (error) {
      onNotify('error', error instanceof Error ? error.message : t('txt_org_member_update_failed'));
    }
  }

  async function handleCreateCollection() {
    if (!selectedOrg) return;
    const name = newCollectionName.trim();
    if (!name) {
      onNotify('error', t('txt_org_collection_name_required'));
      return;
    }
    setCreatingCollection(true);
    try {
      await createCollection(authedFetch, selectedOrg.id, { name });
      setNewCollectionName('');
      onNotify('success', t('txt_org_collection_created'));
      await refreshDetail(selectedOrg.id);
    } catch (error) {
      onNotify('error', error instanceof Error ? error.message : t('txt_org_collection_create_failed'));
    } finally {
      setCreatingCollection(false);
    }
  }

  async function handleDeleteCollection(collectionId: string) {
    if (!selectedOrg) return;
    try {
      await deleteCollection(authedFetch, selectedOrg.id, collectionId);
      onNotify('success', t('txt_org_collection_deleted'));
      await refreshDetail(selectedOrg.id);
    } catch (error) {
      onNotify('error', error instanceof Error ? error.message : t('txt_org_collection_delete_failed'));
    }
  }

  async function handleSaveSso(body: Record<string, unknown>) {
    if (!selectedOrg) return;
    try {
      const updated = await saveSsoConfig(authedFetch, selectedOrg.id, body);
      setSsoConfig(updated);
      onNotify('success', t('txt_org_sso_saved'));
    } catch (error) {
      onNotify('error', error instanceof Error ? error.message : t('txt_org_sso_save_failed'));
    }
  }

  async function handleSaveScim(body: Record<string, unknown>) {
    if (!selectedOrg) return;
    try {
      const updated = await saveScimConfig(authedFetch, selectedOrg.id, body);
      setScimConfig(updated);
      onNotify('success', t('txt_org_scim_saved'));
    } catch (error) {
      onNotify('error', error instanceof Error ? error.message : t('txt_org_scim_save_failed'));
    }
  }

  if (!selectedOrg) {
    return (
      <div className="card stack">
        <div className="settings-section-stack">
          {myInvitations.length > 0 ? (
            <section className="settings-submodule">
              <div className="settings-submodule-header">
                <div>
                  <h2>{t('txt_org_invitations_for_you')}</h2>
                  <p className="muted">{t('txt_org_invitations_for_you_help')}</p>
                </div>
              </div>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>{t('txt_organization')}</th>
                      <th>{t('txt_org_role')}</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {myInvitations.map((invitation) => (
                      <tr key={invitation.id}>
                        <td>{invitation.organizationName}</td>
                        <td>{invitation.role}</td>
                        <td>
                          <button
                            type="button"
                            className="btn btn-primary btn-sm"
                            disabled={invitationBusy === invitation.id}
                            onClick={() => void handleInvitationResponse(invitation, true)}
                          >
                            {t('txt_org_invitation_accept')}
                          </button>
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            disabled={invitationBusy === invitation.id}
                            onClick={() => void handleInvitationResponse(invitation, false)}
                          >
                            {t('txt_org_invitation_decline')}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          ) : null}

          <section className="settings-submodule">
            <div className="settings-submodule-header">
              <div>
                <h2>{t('txt_organizations')}</h2>
                <p className="muted">{t('txt_organizations_help')}</p>
              </div>
              <button type="button" className="btn btn-primary" onClick={() => setShowCreateOrg((value) => !value)} disabled={loading}>
                <Plus size={16} className="btn-icon" />
                {t('txt_create_organization')}
              </button>
            </div>

            {showCreateOrg ? (
              <div className="stack">
                <label className="field">
                  <span>{t('txt_org_name')}</span>
                  <input className="input" value={newOrgName} onInput={(e) => setNewOrgName((e.currentTarget as HTMLInputElement).value)} />
                </label>
                <label className="field">
                  <span>{t('txt_org_identifier')}</span>
                  <input
                    className="input"
                    value={newOrgIdentifier}
                    placeholder={t('txt_org_identifier_placeholder')}
                    onInput={(e) => setNewOrgIdentifier((e.currentTarget as HTMLInputElement).value)}
                  />
                </label>
                <div className="actions">
                  <button type="button" className="btn btn-primary" onClick={() => void handleCreateOrg()} disabled={creatingOrg}>
                    {creatingOrg ? t('txt_creating') : t('txt_create')}
                  </button>
                  <button type="button" className="btn btn-secondary" onClick={() => setShowCreateOrg(false)}>
                    {t('txt_cancel')}
                  </button>
                </div>
              </div>
            ) : null}

            {loading ? (
              <p className="muted">{t('txt_loading')}</p>
            ) : orgs.length === 0 ? (
              <p className="empty">{t('txt_orgs_empty')}</p>
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>{t('txt_org_name')}</th>
                      <th>{t('txt_org_role')}</th>
                      <th>{t('txt_org_status')}</th>
                      <th />
                    </tr>
                  </thead>
                  <tbody>
                    {orgs.map((org) => (
                      <tr key={org.id}>
                        <td>
                          <Building2 size={16} className="btn-icon" />
                          {org.name}
                        </td>
                        <td>{org.role || 'member'}</td>
                        <td>{org.enabled ? t('txt_enabled') : t('txt_disabled')}</td>
                        <td>
                          <button type="button" className="btn btn-secondary" onClick={() => selectOrg(org.id)}>
                            {t('txt_manage')}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>
      </div>
    );
  }

  return (
    <div className="card stack">
      <div className="settings-section-stack">
        <button type="button" className="auth-link-btn" onClick={() => { setSelectedOrgId(null); setMembers([]); setCollections([]); }}>
          <ArrowLeft size={16} className="btn-icon" />
          {t('txt_back_to_organizations')}
        </button>

        <section className="settings-submodule">
          <div className="settings-submodule-header">
            <div>
              <h2>{selectedOrg.name}</h2>
              <p className="muted">
                {t('txt_org_role')}: {selectedOrg.role || 'member'}
              </p>
            </div>
            <button type="button" className="btn btn-secondary" onClick={() => void refreshDetail(selectedOrg.id)} disabled={detailLoading}>
              <RefreshCw size={16} className="btn-icon" />
              {t('txt_refresh')}
            </button>
          </div>
        </section>

        <section className="settings-submodule">
          <div className="settings-submodule-header">
            <div>
              <h2>{t('txt_collections')}</h2>
              <p className="muted">{t('txt_collections_help')}</p>
            </div>
            {manageEnabled ? (
              <div className="actions">
                <input className="input" placeholder={t('txt_org_collection_name')} value={newCollectionName} onInput={(e) => setNewCollectionName((e.currentTarget as HTMLInputElement).value)} />
                <button type="button" className="btn btn-primary" onClick={() => void handleCreateCollection()} disabled={creatingCollection || !newCollectionName.trim()}>
                  <FolderPlus size={16} className="btn-icon" />
                  {t('txt_create')}
                </button>
              </div>
            ) : null}
          </div>
          {collections.length === 0 ? (
            <p className="empty">{t('txt_collections_empty')}</p>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>{t('txt_org_collection_name')}</th>
                    {manageEnabled ? <th /> : null}
                  </tr>
                </thead>
                <tbody>
                  {collections.map((collection) => (
                    <tr key={collection.id}>
                      <td>{collection.name}</td>
                      {manageEnabled ? (
                        <td>
                          <button type="button" className="btn btn-danger btn-sm" onClick={() => void handleDeleteCollection(collection.id)}>
                            <Trash2 size={14} className="btn-icon" />
                            {t('txt_delete')}
                          </button>
                        </td>
                      ) : null}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="settings-submodule">
          <div className="settings-submodule-header">
            <div>
              <h2>{t('txt_members')}</h2>
              <p className="muted">{t('txt_members_help')}</p>
            </div>
            {manageEnabled ? (
              <div className="actions">
                <input className="input" type="email" placeholder={t('txt_org_invite_email_placeholder')} value={inviteEmail} onInput={(e) => setInviteEmail((e.currentTarget as HTMLInputElement).value)} />
                <select className="input" value={inviteRole} onChange={(e) => setInviteRole((e.currentTarget as HTMLSelectElement).value)}>
                  {ORG_ROLE_OPTIONS.map((role) => (
                    <option key={role} value={role}>{role}</option>
                  ))}
                </select>
                <button type="button" className="btn btn-primary" onClick={() => void handleInvite()} disabled={inviting || !inviteEmail.trim()}>
                  <UserPlus size={16} className="btn-icon" />
                  {inviting ? t('txt_inviting') : t('txt_invite')}
                </button>
              </div>
            ) : null}
          </div>
          {members.length === 0 ? (
            <p className="empty">{t('txt_members_empty')}</p>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>{t('txt_email')}</th>
                    <th>{t('txt_org_role')}</th>
                    <th>{t('txt_org_status')}</th>
                    {manageEnabled ? <th /> : null}
                  </tr>
                </thead>
                <tbody>
                  {members.map((member) => (
                    <tr key={member.id}>
                      <td>{member.email}</td>
                      <td>
                        {manageEnabled && member.role !== 'owner' ? (
                          <select
                            className="input"
                            value={member.role}
                            onChange={(e) => void handleChangeMemberRole(member, (e.currentTarget as HTMLSelectElement).value)}
                          >
                            {ORG_ROLE_OPTIONS.map((role) => (
                              <option key={role} value={role}>{role}</option>
                            ))}
                          </select>
                        ) : (
                          member.role
                        )}
                      </td>
                      <td>{member.status === 1 ? t('txt_active') : t('txt_pending')}</td>
                      {manageEnabled ? (
                        <td>
                          {!member.encryptedOrgKey ? (
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              title={t('txt_org_key_missing_hint')}
                              disabled={sharingKeyFor === member.id}
                              onClick={() => void handleShareKey(member)}
                            >
                              <KeyRound size={14} className="btn-icon" />
                              {sharingKeyFor === member.id ? t('txt_saving') : t('txt_org_share_key')}
                            </button>
                          ) : null}
                          {member.role !== 'owner' ? (
                            <button type="button" className="btn btn-danger btn-sm" onClick={() => void handleRemoveMember(member.id)}>
                              <Trash2 size={14} className="btn-icon" />
                              {t('txt_remove')}
                            </button>
                          ) : null}
                        </td>
                      ) : null}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {invitations.length > 0 ? (
            <>
              <h3 className="settings-subheading">{t('txt_pending_invitations')}</h3>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>{t('txt_email')}</th>
                      <th>{t('txt_org_role')}</th>
                      {manageEnabled ? <th /> : null}
                    </tr>
                  </thead>
                  <tbody>
                    {invitations.map((invitation) => (
                      <tr key={invitation.id}>
                        <td>{invitation.email}</td>
                        <td>{invitation.role}</td>
                        {manageEnabled ? (
                          <td>
                            <button
                              type="button"
                              className="btn btn-danger btn-sm"
                              onClick={() => {
                                void revokeOrganizationInvitation(authedFetch, selectedOrg.id, invitation.id).then(() => refreshDetail(selectedOrg.id));
                              }}
                            >
                              <X size={14} className="btn-icon" />
                              {t('txt_revoke')}
                            </button>
                          </td>
                        ) : null}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : null}
        </section>

        {manageEnabled ? (
          <>
            <section className="settings-submodule">
              <div className="settings-submodule-header">
                <div>
                  <h2>
                    <KeyRound size={16} className="btn-icon" />
                    {t('txt_org_sso')}
                  </h2>
                  <p className="muted">{t('txt_org_sso_help')}</p>
                </div>
              </div>
              <div className="stack">
                <label className="field">
                  <span>{t('txt_org_sso_enabled')}</span>
                  <input
                    type="checkbox"
                    checked={ssoConfig?.enabled || false}
                    onChange={(e) => void handleSaveSso({ enabled: (e.currentTarget as HTMLInputElement).checked })}
                  />
                </label>
                <label className="field">
                  <span>{t('txt_org_identifier')}</span>
                  <input
                    className="input"
                    value={ssoConfig?.identifier || ''}
                    placeholder={t('txt_org_identifier_placeholder')}
                    onBlur={(e) => {
                      if (e.currentTarget.value !== (ssoConfig?.identifier || '')) {
                        void handleSaveSso({ identifier: e.currentTarget.value.trim() || null });
                      }
                    }}
                  />
                </label>
                <label className="field">
                  <span>{t('txt_org_sso_provider')}</span>
                  <select className="input" value={ssoConfig?.provider || 'oidc'} onChange={(e) => void handleSaveSso({ provider: e.currentTarget.value })}>
                    <option value="oidc">OIDC</option>
                    <option value="saml">SAML</option>
                  </select>
                </label>
                <label className="field">
                  <span>{t('txt_org_sso_client_id')}</span>
                  <input
                    className="input"
                    value={ssoConfig?.clientId || ''}
                    onBlur={(e) => void handleSaveSso({ clientId: e.currentTarget.value.trim() || null })}
                  />
                </label>
                <label className="field">
                  <span>{t('txt_org_sso_client_secret')}</span>
                  <input
                    className="input"
                    type="password"
                    placeholder={ssoConfig?.clientSecretSet ? '••••••••' : ''}
                    onBlur={(e) => {
                      if (e.currentTarget.value.trim()) void handleSaveSso({ clientSecret: e.currentTarget.value.trim() });
                    }}
                  />
                </label>
                <label className="field">
                  <span>{t('txt_org_sso_issuer')}</span>
                  <input
                    className="input"
                    value={ssoConfig?.issuer || ''}
                    placeholder={t('txt_org_sso_issuer_placeholder')}
                    onBlur={(e) => void handleSaveSso({ issuer: e.currentTarget.value.trim() || null })}
                  />
                </label>
                <label className="field">
                  <span>{t('txt_org_sso_scopes')}</span>
                  <input
                    className="input"
                    value={ssoConfig?.scopes || ''}
                    placeholder="openid email profile"
                    onBlur={(e) => void handleSaveSso({ scopes: e.currentTarget.value.trim() || null })}
                  />
                </label>
              </div>
            </section>

            <section className="settings-submodule">
              <div className="settings-submodule-header">
                <div>
                  <h2>
                    <ShieldCheck size={16} className="btn-icon" />
                    {t('txt_org_scim')}
                  </h2>
                  <p className="muted">{t('txt_org_scim_help')}</p>
                </div>
              </div>
              <div className="stack">
                <label className="field">
                  <span>{t('txt_org_scim_enabled')}</span>
                  <input
                    type="checkbox"
                    checked={scimConfig?.enabled || false}
                    onChange={(e) => void handleSaveScim({ enabled: (e.currentTarget as HTMLInputElement).checked })}
                  />
                </label>
                <div className="actions">
                  <button type="button" className="btn btn-primary" onClick={() => void handleSaveScim({ generateToken: true })}>
                    {t('txt_org_scim_generate_token')}
                  </button>
                </div>
                {scimConfig?.token ? (
                  <p className="field-help">
                    {t('txt_org_scim_token')}: <code>{scimConfig.token}</code>
                  </p>
                ) : scimConfig?.tokenGenerated ? (
                  <p className="field-help">{t('txt_org_scim_token_set')}</p>
                ) : null}
                {scimConfig?.enabled ? (
                  <p className="field-help">
                    {t('txt_org_scim_endpoint')}: <code>{`${window.location.origin}/api/scim/v2`}</code>
                  </p>
                ) : null}
              </div>
            </section>
          </>
        ) : null}
      </div>
    </div>
  );
}
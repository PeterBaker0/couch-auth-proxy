/**
 * Default `_design/acl` body for couch-auth-proxy.
 *
 * Uploaded (or migrated) into application databases. Contains:
 * - `views.acl` map — emits compact ACL rows keyed by doc id
 * - `validate_doc_update` — enforces creator/owners/acl immutability rules
 *
 * IMPORTANT (CouchDB 3.x):
 * - `options.local_seq` still exists, but `_local_seq` is shard-local.
 * - Do NOT compare `_local_seq` to global `_changes` seq strings.
 * - Freshness uses document `_rev`; the cache treats change notifications
 *   as authoritative invalidation keyed by doc id.
 *
 * Map / VDU sources are kept as strings so they upload to CouchDB unchanged.
 */

/** Build a fresh `_design/acl` document (no `_rev`; caller supplies on update). */
export function buildAclDesignDoc(version = "2.3.0") {
  return {
    _id: "_design/acl",
    language: "javascript",
    options: {
      local_seq: true,
      include_design: true,
      // The ACL cache queries one global view, including on partitioned DBs.
      partitioned: false,
    },
    type: "ddoc",
    version,
    stamp: Date.now(),
    acl: [] as string[],
    views: {
      acl: {
        map: ACL_MAP_SOURCE,
      },
    },
    validate_doc_update: VALIDATE_DOC_UPDATE_SOURCE,
  };
}

/**
 * Couch map function source: emit `{ s, p, _r, _w, _d }` per document.
 * Stamp `s` is `doc._rev` (v2). Must stay in sync with `aclRowFromDoc` semantics.
 */
export const ACL_MAP_SOURCE = `function (doc) {
  var r = { s: doc._rev || "", p: "", _r: {}, _w: {}, _d: {} };
  var tmp = "", i, ctr = 0;
  var cr = doc.creator, acl = doc.acl, ow = doc.owners;
  var S = "string", O = "object", F = "function";
  var rr = /^r-/, ru = /^u-/;

  if (typeof cr == S && cr) {
    tmp = cr;
    if (!ru.test(tmp)) tmp = "u-" + tmp;
    r._r[tmp] = r._w[tmp] = r._d[tmp] = 1;
    ctr += 1;
  }

  if (acl != null && typeof acl == O && typeof acl.slice == F) {
    for (i = 0; i < acl.length; i++) {
      tmp = acl[i];
      if (typeof tmp == S) {
        if (rr.test(tmp) || ru.test(tmp)) r._r[tmp] = 1;
        else r._r["u-" + tmp] = 1;
      }
    }
    ctr += 1;
  }

  if (ow != null && typeof ow == O && typeof ow.slice == F) {
    for (i = 0; i < ow.length; i++) {
      tmp = ow[i];
      if (typeof tmp == S) {
        if (!rr.test(tmp) && !ru.test(tmp)) tmp = "u-" + tmp;
        r._r[tmp] = r._w[tmp] = 1;
      }
    }
    ctr += 1;
  }

  if (!ctr) {
    tmp = "r-*";
    if (/^_design/.test(doc._id)) r._r[tmp] = 1;
    else r._r[tmp] = r._w[tmp] = r._d[tmp] = 1;
  }

  if (typeof doc.parent == S) r.p = doc.parent;
  emit(doc._id, r);
}`;

/**
 * Couch `validate_doc_update` source: non-admins cannot forge creator or
 * change owners/acl without standing. Delete authorization belongs to the
 * proxy because parent and dbacl grants are unavailable to Couch's VDU.
 */
export const VALIDATE_DOC_UPDATE_SOURCE = `function (nd, od, userCtx, secObj) {
  var roles = userCtx.roles || [];
  var adm = !!(roles.indexOf("_admin") >= 0);
  var u = userCtx.name;
  var uu = "u-" + u;
  var O = "object";
  var F = "function";
  var S = "string";
  var rr = /^r-/;
  var isA = function (o) {
    return typeof o == O && typeof o.slice == F;
  };

  if (!adm) {
    if (!od) {
      if (nd.creator && nd.creator != u && nd.creator != uu)
        throw { forbidden: "Can't create doc on behalf of other user." };
    } else {
      var odc = od.creator;
      var odw = (isA(od.owners) ? od.owners : []).sort();
      var oda = isA(od.acl) ? od.acl.sort() + "" : "";
      var ndc = nd.creator;
      var ndw = (isA(nd.owners) ? nd.owners : []).sort();
      var nda = isA(nd.acl) ? nd.acl.sort() + "" : "";
      var notCreator = odc != u && odc != uu;
      var notOwner = notCreator && odw.indexOf(u) == -1 && odw.indexOf(uu) == -1;
      var i, roleToken;
      for (i = 0; notOwner && i < roles.length; i++) {
        if (typeof roles[i] == S) {
          roleToken = rr.test(roles[i]) ? roles[i] : "r-" + roles[i];
          if (odw.indexOf(roleToken) >= 0) notOwner = false;
        }
      }
      var odp = typeof od.parent == S ? od.parent : "";
      var ndp = typeof nd.parent == S ? nd.parent : "";

      if (!nd._deleted) {
        if (odc != ndc) throw { forbidden: "Creator can not be changed." };
        if (notCreator && odw + "" != ndw + "")
          throw { forbidden: "Owners list can not be changed." };
        if (notOwner && oda != nda)
          throw { forbidden: "Readers list can not be changed." };
        if (notCreator && odp != ndp)
          throw { forbidden: "Parent can not be changed." };
      }
    }
  }
}`;

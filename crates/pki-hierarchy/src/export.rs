//! Hierarchy export — write certificates and keys to disk

use std::fs;
use std::path::Path;

use crate::builder::BuildResult;
use crate::error::Result;

/// Export a built hierarchy to disk
///
/// Creates directory structure:
/// ```text
/// {output_dir}/
///   {ca_id}/
///     {ca_id}.cert.pem
///     {ca_id}.cert.der
///     {ca_id}.key.pem     (mode 0600)
///     {ca_id}.chain.pem
/// ```
pub fn export_hierarchy(result: &BuildResult, output_dir: &str) -> Result<Vec<String>> {
    let base = Path::new(output_dir);
    let mut exported_files = Vec::new();

    for id in &result.build_order {
        let ca = &result.cas[id];
        let ca_dir = base.join(id);
        fs::create_dir_all(&ca_dir)?;

        // Write certificate PEM
        let cert_pem_path = ca_dir.join(format!("{}.cert.pem", id));
        fs::write(&cert_pem_path, &ca.certificate_pem)?;
        exported_files.push(cert_pem_path.display().to_string());

        // Write certificate DER
        let cert_der_path = ca_dir.join(format!("{}.cert.der", id));
        fs::write(&cert_der_path, &ca.certificate_der)?;
        exported_files.push(cert_der_path.display().to_string());

        // Write private key PEM (restricted permissions)
        let key_path = ca_dir.join(format!("{}.key.pem", id));
        fs::write(&key_path, ca.private_key_pem.as_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
        }
        exported_files.push(key_path.display().to_string());

        // Write chain PEM
        let chain_path = ca_dir.join(format!("{}.chain.pem", id));
        fs::write(&chain_path, &ca.chain_pem)?;
        exported_files.push(chain_path.display().to_string());
    }

    Ok(exported_files)
}

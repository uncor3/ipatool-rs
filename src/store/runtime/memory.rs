use crate::{
    error::ClientError,
    sap::{macho::Memory, unicorn::Guest},
};
use std::cell::RefCell;
use std::collections::HashSet;

pub(super) fn failure(message: impl Into<String>) -> ClientError {
    ClientError::Sap(message.into())
}

pub(super) fn group_pages(mut addresses: Vec<u64>) -> Result<Vec<(u64, u64)>, ClientError> {
    addresses.sort_unstable();
    addresses.dedup();
    if addresses
        .iter()
        .any(|a| a % 4096 != 0 || a.checked_add(4096).is_none())
    {
        return Err(failure("invalid Store profile page address"));
    }
    let mut result = Vec::new();
    let mut total = 0;
    let mut start = 0;
    while start < addresses.len() {
        let mut end = start + 1;
        while end < addresses.len()
            && addresses[end] - addresses[end - 1] <= 1 << 20
            && addresses[end] - addresses[start] + 4096 <= 32 << 20
        {
            end += 1;
        }
        let size = addresses[end - 1] - addresses[start] + 4096;
        if size > (1 << 30) - total {
            return Err(failure("Store profile mapping exceeds size limit"));
        }
        total += size;
        result.push((addresses[start], size));
        start = end;
    }
    Ok(result)
}

pub(super) struct Mapper<'a> {
    pub guest: Guest<'a>,
    pub pages: RefCell<HashSet<u64>>,
}
impl Memory for Mapper<'_> {
    fn map(&self, address: u64, size: u64) -> Result<(), ClientError> {
        if !address.is_multiple_of(4096)
            || !size.is_multiple_of(4096)
            || address.checked_add(size).is_none()
        {
            return Err(failure("invalid Store memory mapping"));
        }
        let mut pages = self.pages.borrow_mut();
        let end = address + size;
        let mut page = address;
        while page < end {
            if pages.contains(&page) {
                page += 4096;
                continue;
            }
            let start = page;
            page += 4096;
            while page < end && !pages.contains(&page) {
                page += 4096;
            }
            self.guest.mem_map(start, page - start)?;
            for mapped in (start..page).step_by(4096) {
                pages.insert(mapped);
            }
        }
        Ok(())
    }
    fn write(&self, address: u64, data: &[u8]) -> Result<(), ClientError> {
        self.guest.mem_write(address, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn grouping_is_bounded_and_deduplicated() {
        assert_eq!(
            group_pages(vec![8192, 4096, 4096, 0x4000000]).unwrap(),
            vec![(4096, 8192), (0x4000000, 4096)]
        );
        assert!(group_pages(vec![1]).is_err());
        assert!(group_pages(vec![u64::MAX - 4095]).is_err());
        let regions = group_pages((0..100).map(|i| i * 1024 * 1024).collect()).unwrap();
        assert!(regions.iter().all(|(_, size)| *size <= 32 << 20));
    }
}

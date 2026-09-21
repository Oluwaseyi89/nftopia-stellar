/**
 * Re-export address book store for lib/stores path compatibility.
 * Primary implementation lives at @/stores/addressBookStore
 */
export * from '@/stores/addressBookStore';
export { useAddressBookStore as default } from '@/stores/addressBookStore';

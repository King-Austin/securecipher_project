export const generateUsername = (firstName, lastName) => {
  if (!firstName || !lastName) return '';
  
  // Clean and format the names
  const cleanFirst = firstName.toLowerCase().replace(/[^a-z0-9]/g, '');
  const cleanLast = lastName.toLowerCase().replace(/[^a-z0-9]/g, '');
  
  // Generate random number between 1000-9999
  const randomNum = Math.floor(Math.random() * 9000) + 1000;
  
  return `${cleanFirst}${cleanLast}${randomNum}`;
};
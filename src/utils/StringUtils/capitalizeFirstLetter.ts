export default function capitalizeFirstLetter(str: string) {
  if (!str) return '';

  var firstCodeUnit = str[0];

  if (firstCodeUnit < '\uD800' || firstCodeUnit > '\uDFFF') {
    return str[0].toUpperCase() + str.slice(1);
  }

  return str.slice(0, 2).toUpperCase() + str.slice(2);
}

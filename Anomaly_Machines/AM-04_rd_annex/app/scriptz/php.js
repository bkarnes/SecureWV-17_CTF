// DIRECTIVE ZERO — AM-04 scriptz/php.js
// A JS port of PHP's serialize() function. Players who view the page
// source see this referenced and can understand the serialization format
// used in the `param` POST field.
// (Minimized version of the phpjs.org serialize implementation.)

function serialize(mixed_value) {
    var val, type = typeof mixed_value;
    if (type === 'undefined') return 'N;';
    if (type === 'boolean') return 'b:' + (mixed_value ? '1' : '0') + ';';
    if (type === 'number') {
        if (mixed_value % 1 === 0 && mixed_value <= 1e15 && mixed_value >= -1e15)
            return 'i:' + mixed_value + ';';
        return 'd:' + mixed_value + ';';
    }
    if (type === 'string') {
        var utf8len = 0;
        for (var i = 0; i < mixed_value.length; i++) {
            var c = mixed_value.charCodeAt(i);
            if (c < 128) utf8len++;
            else if (c < 2048) utf8len += 2;
            else utf8len += 3;
        }
        return 's:' + utf8len + ':"' + mixed_value + '";';
    }
    if (type === 'object' || type === 'array') {
        if (mixed_value === null) return 'N;';
        var count = 0, items = '';
        for (var key in mixed_value) {
            if (mixed_value.hasOwnProperty(key)) {
                var k = /^\d+$/.test(key) ? 'i:' + key + ';' : serialize(key);
                items += k + serialize(mixed_value[key]);
                count++;
            }
        }
        return 'a:' + count + ':{' + items + '}';
    }
    return 'N;';
}
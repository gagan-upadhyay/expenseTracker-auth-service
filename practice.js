// const obj={
//     name:"abcd",
//     getName(){
//         return this.name;
//     }
// }
// console.log(obj.getName());

// function abcd(str, char){
//     return str.split(char).length-1;
// }
// console.log(abcd('asdfghjkiiiil', 'i'))

// function fartocel(cels){
//     return (cels*9/5)+32;
// }
// console.log(fartocel(36));

//sort in ascendoing order:

// function sortAsc(arr){
//     return arr.sort((a,b)=>b-a);
// }

// console.log(sortAsc([4,6,1,6,9,0]));

// intersection of two arrays:

// function intersection(arr1, arr2){
//     const set2 = new Set(arr2);
//     const seen = new Set();
//     const out = [];

//     for(const x of arr1){
//         if(set2.has(x) && !seen.has(x)){
//             out.push(x);
//             seen.add(x);
//         }
//     }
//     return out
// }
// console.log(intersection([1,2,3, 4, 3, 2, 8,4], [1,8, 3,4,5, 4, 3]))

// union

// function union(arr1, arr2){
//     return [... new Set([...arr1, ...arr2])]
// }
// console.log(union([1,2,3, 4, 3, 2, 8,4], [1,8, 3,4,5, 4, 3]));

// function fun(str) {
//     const charCount = {};
//     const arr=[];

//     // count the occurrences of each character
//     for (let char of str) {
//         // console.log(charCount[char]);
//         charCount[char] = (charCount[char] || 0) + 1;
//     }
//     console.log();
//     // find the first non-repeated character
//     for (let char of str) {
//         if (charCount[char] === 1) {
//             console.log(char);
//             console.log(typeof arr);
//             arr.push(char)
//             // return char;
//         }
//     }

//     return arr;
// }

// console.log(fun('GeeksForGeeks'));

//longest word in string:

// function longestWord(str){
//     const words = str.split(' ');
//     let longest = '';
//     for(let word of words){
//         if(word.length>=longest.length){
//             longest = word;
//         }
//     }
//     return longest;

// }

// console.log(longestWord('this is the best enthi time to enjoy your life'));

//capitalize first letter:

// function capitalize(str){
//     const words = str.split(' ');
//     console.log(words);
//     for(let i =0; i<words.length;i++){
//         words[i]=words[i].charAt(0).toUpperCase()+words[i].slice(1);
//     }
//     return words.join(' ')
// }
// console.log(capitalize('hello world'));


//capitalize array of string

// function capitalize(arr){
//     for(let i=0; i<arr.length;i++){
//         arr[i]=arr[i].toUpperCase();
//     }
//     return arr;
// }
// console.log(capitalize(['a', 'b', 'c']));

// function areAnagrams(str1, str2){
//     if(str1.length!==str2.length) return false;

//     const count1={};
//     const count2={};
//     for(let i=0;i<str1.length;i++){
//         let char = str1[i];
//         count1[char]=(count1[char]||0)+1
//     }
//     for(let i=0;i<str2.length;i++){
//         let char = str2[i];
//         count2[char] = (count2[char]||0)+1;
//     }
//     for(let char in count1){
//         if(count1[char]!==count2[char]){
//             return false;
//         }
//     }
//     return true;
// }
// console.log(areAnagrams('silent', 'lisen2'));

// function maxDifference(arr){
//     let min=arr[0];
//     let maxDiff =0;

//     for(let i =1; i<arr.length;i++){
//         const diff = arr[i]-min;
//         maxDiff=Math.max(maxDiff, diff);
//         min=Math.min(min, arr[i]);

//     }
//     return maxDiff;
// }
// console.log(maxDifference([1,4,2,100,45]));

//remove duplicates

// function removeDuplicates(arr){
//     const uniqueArray=[];
//     for(let i=0; i<arr.length;i++){
//         if(!uniqueArray.includes(arr[i])){
//             uniqueArray.push(arr[i]);
//             // console.log('Value of uniqueArray:', uniqueArray);
//         }
//     }
//     return uniqueArray;
// }

// console.log(removeDuplicates([1,22,5,4,-3, 3,2,2,22,99,43,-90,-90,-3,]));

// function countVowel(str){
//     const vowels = 'aeiouAEIOU'
//     let count=0;
//     let vowelCount = {}
//     for(let i=0;i<str.length;i++){
//         if(vowels.includes(str[i])){
//             vowelCount[str[i]] = (vowelCount[str[i]]||0)+1;
//             count++;
//         }
//     }
//     return [count, vowelCount];

// }
// console.log(countVowel('equation of cauliflower'));

//roman to numerals:

// function value(r){
//     if(r==='I'){
//         return 1;
//     }
//     if(r==='V'){
//         return 5;
//     }
//     if(r==='X'){
//         return 10;
//     }
//     if(r==='L'){
//         return 50;
//     }
//     if(r==='C'){
//         return 100
//     }
//     if(r==='D'){
//         return 500; 
//     }
//     if(r==='M'){
//         return 1000;
//     }
//     return -1;
// }

// function romanToDecimal(s){
//     let res=0;
//     for(let i=0; i<s.length;i++){
//         let s1= value(s[i]);
//         if(i+1<s.length){
//             let s2=value(s[i+1]);
//             if(s1>=s2){
//                 res+=s1;
//             }else{
//                 res+=(s2-s1)
//                 i++;
//             }
//         }else{
//             res+=s1;
//         }
        
//     }
//     return res;
// }
// console.log(romanToDecimal('LVL'));

function rate(limit){
    let count =0;
    return function(){
        count++;
        return count<=limit;
    };
}

const limiter = rate(3)
console.log(limiter());
console.log(limiter());
console.log(limiter());
console.log(limiter());
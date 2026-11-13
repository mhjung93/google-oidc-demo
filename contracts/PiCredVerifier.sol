// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract PiCredVerifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 15378472896279502874932323006149719636276078713581518549514751911818508891003;
    uint256 constant deltax2 = 18683068361279158321375403214352168893840447306602415481816319221652058559823;
    uint256 constant deltay1 = 14200438177480136734370729856380765558081673540790719234060933187011570845897;
    uint256 constant deltay2 = 21886433569574490482329645128576906519862214210425435074409119345541769296415;

    
    uint256 constant IC0x = 56603879841708020285759618439022147628306317834134820599301579981052925417;
    uint256 constant IC0y = 403054249373627069482016541405493772361614509515706031624630382212728459661;
    
    uint256 constant IC1x = 1456885646772267304788488263717606298888232393161045479128889487709517633459;
    uint256 constant IC1y = 468621277878778368592684682488344297713244487592776502907753187267432849270;
    
    uint256 constant IC2x = 12089599810377205316652531531746959541165242901818501384191355771432462172128;
    uint256 constant IC2y = 306802133226285969029383785472730163853094802384062401248712635072022206962;
    
    uint256 constant IC3x = 20307380069280375198749726445582943006197599342814276079264973053389376623812;
    uint256 constant IC3y = 6151331129676379233141808966923289301223263696578773987189633940313512191094;
    
    uint256 constant IC4x = 20045273414324543984328762349357328058497066588480609365428751706068967992221;
    uint256 constant IC4y = 11130294757948180156715516014555961195548816455455182390592605212100919250822;
    
    uint256 constant IC5x = 14351187967100913496150425821749880932837475517011941695140572230506228171654;
    uint256 constant IC5y = 13751356185642811815630690282345025133509575178468531838297719146616299106628;
    
    uint256 constant IC6x = 13078799204801866016255863516676334627972388019132444812082005366919840528376;
    uint256 constant IC6y = 10227010903977566940958170519146337669099504837998977431663804456222830531118;
    
    uint256 constant IC7x = 3828601189927226814511473522016659764652273202441964797234194604185200884797;
    uint256 constant IC7y = 15506162355248662499997575238555649785672954723840349309524172730530639105534;
    
    uint256 constant IC8x = 14742457111393160465425894841099531940168899264633143654514519403593911088004;
    uint256 constant IC8y = 20448295460045414971169983717473875718858178087050858339927163095181010126708;
    
    uint256 constant IC9x = 2051854066073457168916158254809005137165079513223798273204696013406898647040;
    uint256 constant IC9y = 19846094171282850297019020747794177438936690708468470090026068313155145457591;
    
    uint256 constant IC10x = 10318212100355419408146436281611609568594264042313122849209232863351066190828;
    uint256 constant IC10y = 6917864887800281493943793240128384866367765178298494037196034341100811815283;
    
    uint256 constant IC11x = 11363645717959279532380346945184760025046584592957378540065897929094597187782;
    uint256 constant IC11y = 11592015113251362775104185772598104663401012505261493132249536532939403161;
    
    uint256 constant IC12x = 514711325729217131092947230304420383873536315503260181840955588856588961985;
    uint256 constant IC12y = 9071366449014573965011388672701785584896403413150301931075645206865165213662;
    
    uint256 constant IC13x = 18685472136794470880702695004254357006097028403230963950878560046354115867388;
    uint256 constant IC13y = 9499351514187440968676958416862767081171020494134672863878773055483725042355;
    
    uint256 constant IC14x = 3989939334275575788631192618022676246146505663788091173280119053973382250089;
    uint256 constant IC14y = 4160587394078602766851640497836746635195703540014016528935739948752732269528;
    
    uint256 constant IC15x = 16781395759422533177832881379386446219645600821166445184926431796270234027018;
    uint256 constant IC15y = 5670046247514395086457999151623220299083977114216814624807033384731022357715;
    
    uint256 constant IC16x = 4084903298805347095615353779075745092675772381355263210408945470117757044047;
    uint256 constant IC16y = 6104213174536351049410450409655718270158788138743541204450281395293205727653;
    
    uint256 constant IC17x = 15189617572216702448995536368806699006291711954302467904576309536938596893872;
    uint256 constant IC17y = 17507901841597169954801657295507780944249502297570739463256119936358294247298;
    
    uint256 constant IC18x = 4970583153531407231500275898085360068687511091763702527365791135333107822756;
    uint256 constant IC18y = 14799501079903890183696076299372905708150137136196667433090088068975782271231;
    
    uint256 constant IC19x = 2599307052215990596167253543224017455990618489134388862320042524385282745022;
    uint256 constant IC19y = 3365707743674607174067347423093605829114486394396172266639333304703400402406;
    
    uint256 constant IC20x = 14939551121752587260737804907900676304161039241923017669600688235614934172640;
    uint256 constant IC20y = 13463214041988774489558733342277096161675810386772190734699290437445074455144;
    
    uint256 constant IC21x = 8969147640326011343452993321705842282108799924726390579034373757138859141475;
    uint256 constant IC21y = 11644593754442400488166108066098953881287336113248150173678552820469454375985;
    
    uint256 constant IC22x = 2312788203949340349628108612783788941298689036163420427272504134714344418393;
    uint256 constant IC22y = 8756749640893434437930335924098574555498012984988948856385987590049932833202;
    
    uint256 constant IC23x = 14893219640797197126947872467360014859007676006620775091586338193142842182013;
    uint256 constant IC23y = 6643895819769113682892682567275151861899275702689332135764480680812589504816;
    
    uint256 constant IC24x = 21770306987736290477543978768004166216848838209578127849263091126949930693992;
    uint256 constant IC24y = 12326806078057114846104738556845767092825142418408852956059548290352357886045;
    
    uint256 constant IC25x = 1149669047238662612973578374877029686348220431183293141047300122468862770896;
    uint256 constant IC25y = 15140512706915485696636316674816558117528773220749935364636427162550419255635;
    
    uint256 constant IC26x = 16532087417271166410739896163094924459373242634626932360474339717658009553659;
    uint256 constant IC26y = 13424473792001876061837047923978342408217010526442107276796213091480718791994;
    
    uint256 constant IC27x = 10168585044773715857339113379465925104575393162165888283449513008368737928574;
    uint256 constant IC27y = 17224473787538572036261782415656439115594213229066639710895810111127936889203;
    
    uint256 constant IC28x = 9030928024036011789127816542689990527383796541070813438996814903643860691094;
    uint256 constant IC28y = 17646710863767416110354006832061501001552250420744088607355406161263464950955;
    
    uint256 constant IC29x = 21284834384782976490402197479477089647174702559576298468414077441807821214743;
    uint256 constant IC29y = 3680257743996509374684995572065979541737557314839927472429580753127818618935;
    
    uint256 constant IC30x = 10746503324262115293282501224083815085730474686229409471110392754735855448808;
    uint256 constant IC30y = 11068844351733166994957412895935003376875884935533392066466433183807799107492;
    
    uint256 constant IC31x = 17426722474776124634260314283595391361604756367804227830397531537466445131787;
    uint256 constant IC31y = 3113841176971745483563774703518203376363329775750520156593483842986763378608;
    
    uint256 constant IC32x = 15688851812536453596945661960478686650775893331538461712259046549259091203271;
    uint256 constant IC32y = 331427430642822711738495994944498636407486336232027296913937862164519891744;
    
    uint256 constant IC33x = 16656520810080385205915552504917937667266688145484886576296662548404547971208;
    uint256 constant IC33y = 8530568184160889964429318361531958890557689798259104734532207380092531022538;
    
    uint256 constant IC34x = 8604270149735486552989155214978838401060481271710469754773947864316739039437;
    uint256 constant IC34y = 14502243587567450357265597354973202499788782581748742401678258772165689552394;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[34] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                
                g1_mulAccC(_pVk, IC22x, IC22y, calldataload(add(pubSignals, 672)))
                
                g1_mulAccC(_pVk, IC23x, IC23y, calldataload(add(pubSignals, 704)))
                
                g1_mulAccC(_pVk, IC24x, IC24y, calldataload(add(pubSignals, 736)))
                
                g1_mulAccC(_pVk, IC25x, IC25y, calldataload(add(pubSignals, 768)))
                
                g1_mulAccC(_pVk, IC26x, IC26y, calldataload(add(pubSignals, 800)))
                
                g1_mulAccC(_pVk, IC27x, IC27y, calldataload(add(pubSignals, 832)))
                
                g1_mulAccC(_pVk, IC28x, IC28y, calldataload(add(pubSignals, 864)))
                
                g1_mulAccC(_pVk, IC29x, IC29y, calldataload(add(pubSignals, 896)))
                
                g1_mulAccC(_pVk, IC30x, IC30y, calldataload(add(pubSignals, 928)))
                
                g1_mulAccC(_pVk, IC31x, IC31y, calldataload(add(pubSignals, 960)))
                
                g1_mulAccC(_pVk, IC32x, IC32y, calldataload(add(pubSignals, 992)))
                
                g1_mulAccC(_pVk, IC33x, IC33y, calldataload(add(pubSignals, 1024)))
                
                g1_mulAccC(_pVk, IC34x, IC34y, calldataload(add(pubSignals, 1056)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            
            checkField(calldataload(add(_pubSignals, 672)))
            
            checkField(calldataload(add(_pubSignals, 704)))
            
            checkField(calldataload(add(_pubSignals, 736)))
            
            checkField(calldataload(add(_pubSignals, 768)))
            
            checkField(calldataload(add(_pubSignals, 800)))
            
            checkField(calldataload(add(_pubSignals, 832)))
            
            checkField(calldataload(add(_pubSignals, 864)))
            
            checkField(calldataload(add(_pubSignals, 896)))
            
            checkField(calldataload(add(_pubSignals, 928)))
            
            checkField(calldataload(add(_pubSignals, 960)))
            
            checkField(calldataload(add(_pubSignals, 992)))
            
            checkField(calldataload(add(_pubSignals, 1024)))
            
            checkField(calldataload(add(_pubSignals, 1056)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }

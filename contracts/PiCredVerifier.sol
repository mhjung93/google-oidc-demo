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
    uint256 constant deltax1 = 3737523247958840618234110746575286163608020577469550568932117230339828609977;
    uint256 constant deltax2 = 1200634262003850514978841274727795521224734869114257781377733293799669975530;
    uint256 constant deltay1 = 9710697679678325682775233384778818005711623744433713000298462527803397428527;
    uint256 constant deltay2 = 16594204251802692588980575590740098356186266951108748948150518523489956215690;

    
    uint256 constant IC0x = 18616471042604691369144161761437366651523249041704716641350770637409003933557;
    uint256 constant IC0y = 10123687652149973732607926484450133293363512958803351749331596242490238068924;
    
    uint256 constant IC1x = 20974532098461272141734834840243207061354372984768483909926891465707736595602;
    uint256 constant IC1y = 13755499852904220778291751989235965582365075327581745504382392064983333383497;
    
    uint256 constant IC2x = 3003325263921094939879144854349129081010253375405930520293649621780589197992;
    uint256 constant IC2y = 9694171026580193319015742958906153536620131461106864278288218307787130843851;
    
    uint256 constant IC3x = 19930600103564361828233583108422872002480808142950377949094900745614537000097;
    uint256 constant IC3y = 9895309064034926456853003261697455180650094059780523044043159944836691818313;
    
    uint256 constant IC4x = 196996354866503007491454691606181118248247995995570819786368468274358925444;
    uint256 constant IC4y = 5715997303919867135197479290449223134744259251504174698935296534710804731893;
    
    uint256 constant IC5x = 14320467670432365087481202393016874849228458646444913391357892546488439439340;
    uint256 constant IC5y = 10443644192350700807309184036951740531329886709804812556866427767854060624700;
    
    uint256 constant IC6x = 17747970160385845990215938869370684066299865309520258722105509414585153421209;
    uint256 constant IC6y = 7562937508752387056698113209997970543462284539895105838816300851461541871705;
    
    uint256 constant IC7x = 1503921447868966879059021812401763989856435694228750818149052921907522245955;
    uint256 constant IC7y = 20355905219552621164385054391851245481879589196584310405597765354633505084277;
    
    uint256 constant IC8x = 4520391359490688398330144070926411742104067986341346881724920418840323699629;
    uint256 constant IC8y = 19309169956347214967984267594931936364881073024981655896828832717643567321290;
    
    uint256 constant IC9x = 1866318027249408224189777449768367787099842709956467519390889361643426227095;
    uint256 constant IC9y = 4935253093560172345889034302443150764240484849847239280794051515477285156050;
    
    uint256 constant IC10x = 14582145817203677177820014700583323914753102501779874895969844319039876049039;
    uint256 constant IC10y = 16989647629954891994089235329574259563821057733159920449214264233199831286410;
    
    uint256 constant IC11x = 19672221804306198095060788422189684603659820787606124039519907556985439438284;
    uint256 constant IC11y = 18588433095646907480874132803853278993492789583758360888700861226595145174671;
    
    uint256 constant IC12x = 3788549682801362705405874263787181789597712853817395749058856982833318385509;
    uint256 constant IC12y = 2843189072573765477189659611234734443478512408834939355781645510969238579630;
    
    uint256 constant IC13x = 4911996703082113951809287915479315856922670389081672208583022274552149703035;
    uint256 constant IC13y = 9633193758483077914901268171299884972420310120631600061828241568160410022972;
    
    uint256 constant IC14x = 4701349107123452503084790752401678919005233813298133745682318756153451785376;
    uint256 constant IC14y = 1648646291100704459606073065569988063616188781399495945580119893520457511446;
    
    uint256 constant IC15x = 1041246390922719362245310586769921774797880658664001795591180360033071945005;
    uint256 constant IC15y = 20371568167433709526595719435515764622762494350394921303293583569104966695757;
    
    uint256 constant IC16x = 17406650588529882690530028581973977719482982709997457865024410666231089786094;
    uint256 constant IC16y = 8801335497820465691670348438949237604188543779234906906362047348161273853861;
    
    uint256 constant IC17x = 8961119564950941390372159217438778040455346428661250151642313932966577424212;
    uint256 constant IC17y = 10104261513858483200602650034211558419276411567827657182384044219467028622752;
    
    uint256 constant IC18x = 5973039312255262460702005117827103573723707563263519802447267312519887072837;
    uint256 constant IC18y = 2197477649186005031196962424342300204604369279750008857182506382077375576027;
    
    uint256 constant IC19x = 6662348765809689375253346668699836019706469796434758683321534226005346230801;
    uint256 constant IC19y = 11376331435422933494484825232115666683493947202247995825086355341866438238556;
    
    uint256 constant IC20x = 14903293354836923859845278885833973238128760699238133093453742122235250629232;
    uint256 constant IC20y = 14111210373284643229427097467177293597318022031491221477527111179977925438826;
    
    uint256 constant IC21x = 7295097549693703475850844512830938837389826485793292925735156396209691177463;
    uint256 constant IC21y = 15924527631332942245502627750021027465103409698895235906893163250672761890041;
    
    uint256 constant IC22x = 755013164504545947815536784505813588007923263761447169662128765786259820435;
    uint256 constant IC22y = 1683980175627694174540480561291141642575515699801402016356826244376437680618;
    
    uint256 constant IC23x = 14971657178865956703806460946508822149761589306430230499027403993514742694865;
    uint256 constant IC23y = 21372220510734207797001696482709244525076639465577472266946830659845538267034;
    
    uint256 constant IC24x = 14623063235543499374699331765204118622560899624496972532353934939348197091285;
    uint256 constant IC24y = 16024075107254330851716458344623953486299677081357039603694794002740776682431;
    
    uint256 constant IC25x = 15751017093987333253860421585305566472056565351233558923102520696021222723600;
    uint256 constant IC25y = 16201842970848392496478422855714397513749926199430991383591112246256091424059;
    
    uint256 constant IC26x = 6631423103979110536251729025140479101109796976582830649863752606904051218195;
    uint256 constant IC26y = 18908433530512036134943658405125230236450779232362561342410312635755835041850;
    
    uint256 constant IC27x = 10557094478932330115028818255665826535241648706973093124866432513066144426203;
    uint256 constant IC27y = 6517092402083659825055030324649987733135234964765459496411818897218786848815;
    
    uint256 constant IC28x = 20719173438085397392555888426540853646768975443061438974280834175073156042078;
    uint256 constant IC28y = 17356459324921846855564388909302845311432220392768499376717938287453961811301;
    
    uint256 constant IC29x = 1523859112186724890686458431214618842284080292231373597093517189417801939429;
    uint256 constant IC29y = 17992544304716278539226666098250375843377101845901871279755079562250292585474;
    
    uint256 constant IC30x = 6713843385497184430911054592539658996475682453581921662890195389671538506573;
    uint256 constant IC30y = 13236646278584682823322602316608450920620091958147800868015498302777873333178;
    
    uint256 constant IC31x = 12771135076993849888764737654327754849824256274650669791539164714316195691097;
    uint256 constant IC31y = 750387057087745372282427003827651828034002509757734873688064945994121384328;
    
    uint256 constant IC32x = 14247871825264208268433268471296512371160493066353462258318048553255011980034;
    uint256 constant IC32y = 1047843450023132852458402855984138153165472692007105071421844500939191644557;
    
    uint256 constant IC33x = 1298150795311073784836177172117625042058355575234690307561292631001279303412;
    uint256 constant IC33y = 249364025808981522650963930234965980786433237268009856740103958764722157542;
    
    uint256 constant IC34x = 18967732478524392608716926393649245316796185525890223705350206094401667786527;
    uint256 constant IC34y = 17072739544605680676827482007853899757848964852830093089653182281990622474761;
    
 
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

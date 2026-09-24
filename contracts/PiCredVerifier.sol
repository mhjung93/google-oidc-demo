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
    uint256 constant deltax1 = 7860879034458183754421978969417088611939406122700729162209446663435148298188;
    uint256 constant deltax2 = 2780696741563212141533989746128832292998064056244430561507270735421508271380;
    uint256 constant deltay1 = 9675366501330058702786355668370860315691482480542799191930719949190191229444;
    uint256 constant deltay2 = 20642432161925457106509381662868235819050313218698205290937254738314101746164;

    
    uint256 constant IC0x = 8680898053842276852266620236582848763692503469813771090548811217404988164826;
    uint256 constant IC0y = 6681251040389367983606138042059795556487918976440802399543215889822876228408;
    
    uint256 constant IC1x = 20132768550402427954989312298533472941073201495612403020539161364761467385367;
    uint256 constant IC1y = 20980973565832843894224964062205499171973837951371436182019653858714379268481;
    
    uint256 constant IC2x = 7112688075992900248870841924194006502330566945638975642975679147336162349366;
    uint256 constant IC2y = 10844171325487741889273900095549919218304054870989728757571196946129440067467;
    
    uint256 constant IC3x = 14478406389749813380344962252445355479928459733088338371053496822255316199284;
    uint256 constant IC3y = 18483082250219709134837201316390369998008490981888071476500430858881051404510;
    
    uint256 constant IC4x = 20100541647688007449737157550971791660701539909381696277244085963980351112777;
    uint256 constant IC4y = 12081047653100370117557910170384294873046128948839588133604958682104459587597;
    
    uint256 constant IC5x = 3937304034051474546292491414172892104344647456828049998234474092474549341554;
    uint256 constant IC5y = 3491789703021208644454128271372879776581434603049828739531416988351795221503;
    
    uint256 constant IC6x = 11307655402657963692804338093585796116213308995335437776648881377108588994906;
    uint256 constant IC6y = 5492343372835975787407574885788588798527412024673351108811415842624606708351;
    
    uint256 constant IC7x = 5343467005272525111652417262771379454452788020821067869978058643222563412557;
    uint256 constant IC7y = 20340276639114998103613938379509552801450792793514114588444233663270006188860;
    
    uint256 constant IC8x = 6704409820342794824386307732981406947888461550317396387819868395169898891904;
    uint256 constant IC8y = 19113240863670460135291270056784176107183348830543823123198615019179556497673;
    
    uint256 constant IC9x = 328495735841922442456531997369904696339338265582529860272641908682627360912;
    uint256 constant IC9y = 5491506562282937730773146648083775963803235738216390190811921468877984435154;
    
    uint256 constant IC10x = 1920626577073793182826831607511170014199121317281986015904466945542421863885;
    uint256 constant IC10y = 15853598990389256887919108866085606537104275485101125142347109193339433356571;
    
    uint256 constant IC11x = 2628200244706821268192664015213636288375082140892567402958453428435060466371;
    uint256 constant IC11y = 16824337887906492350046242502416385026557215284079605370976835544907628883619;
    
    uint256 constant IC12x = 17612676222696601541318813026112029222619613461733764839363630851834107183829;
    uint256 constant IC12y = 19770438808639906528207814766551232915182315412229273920207999979250772700536;
    
    uint256 constant IC13x = 12185845267272273095087477081801803955416441317892826758304154664393826764645;
    uint256 constant IC13y = 7583034032586579404542681802127497675718882346479220213305151089371027261539;
    
    uint256 constant IC14x = 15762079283026039581165054760306698426651809063390506988175750451867746490492;
    uint256 constant IC14y = 11520897982745435359136105468317172727006343997317786141141338157377257964628;
    
    uint256 constant IC15x = 10546340537833301301062937126527122959450370417416838357407647796258744359266;
    uint256 constant IC15y = 20261755413451163773996400987658410349518996261121337598589204509613143446212;
    
    uint256 constant IC16x = 16885036792177424694005194003297975130521247097690845887274845031012211986014;
    uint256 constant IC16y = 16877692150037435565383707968071529587556293401953518089874048700227077146906;
    
    uint256 constant IC17x = 13091358656890767546894485105555424999211127673467251304778469967979705186185;
    uint256 constant IC17y = 4231644359656133891668134382346485419492299889642270239938984435186631891502;
    
    uint256 constant IC18x = 4296212703701065646206998756060074084009371000489323692005576402913786493024;
    uint256 constant IC18y = 4147301267109121442115905086929714632775119802553265516100372903546669831750;
    
    uint256 constant IC19x = 17014544833219928311800357727621470769190321912035114466924976133419907561471;
    uint256 constant IC19y = 6162382386303834015463031192610192638404291660327219639750158110285175849305;
    
    uint256 constant IC20x = 12599215694647898645095209886143216297981849148133191439732370871906770871006;
    uint256 constant IC20y = 10197674725768238283803667054341140471277446639789803484839668627689421433201;
    
    uint256 constant IC21x = 4478344979891476938802106978973715769138035525336119415120276914395207003682;
    uint256 constant IC21y = 13314647803633536747046935007733334872696226578537610446283372603569125063268;
    
    uint256 constant IC22x = 16864551363870231969030004550364464168816474784568348961123278564404506141193;
    uint256 constant IC22y = 16525435726896928503576123566954605429091106878859038386297226640311220363844;
    
    uint256 constant IC23x = 19455647382836608180219639728559860390473492973967568038096255665555446043211;
    uint256 constant IC23y = 2185391456732116462991065811172344704588653415365256314066791027748392487923;
    
    uint256 constant IC24x = 988938960509043066035323256530739460631942237581910278477672701388195862552;
    uint256 constant IC24y = 19563489401592453844946301895808462805112928968769043454063781485934885889499;
    
    uint256 constant IC25x = 14198102092773018359999761525186659005802522612865701554629967465723729329411;
    uint256 constant IC25y = 19221746042897372795499291903925952966657154786512536383919100620194871357051;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[25] calldata _pubSignals) public view returns (bool) {
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
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }

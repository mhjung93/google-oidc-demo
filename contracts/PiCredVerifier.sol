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
    uint256 constant deltax1 = 21108573258197839730657510742628142431501613478312651089399201062797838164298;
    uint256 constant deltax2 = 2442322837354057855763883514220742093900848490456667248135468086442924862868;
    uint256 constant deltay1 = 7666804973962778059792095021699544766340951656703561381757539802891336106948;
    uint256 constant deltay2 = 6050297749846408739021345113683052589214454380424111292281748958344495418987;

    
    uint256 constant IC0x = 11916154303078435470503485798668272991792782741003933871711841784804686153573;
    uint256 constant IC0y = 18073465734914162141920467938906125758724149670926771658610407089538787020507;
    
    uint256 constant IC1x = 20820992656903432997370379305322734063122963409282941946829331404366708923307;
    uint256 constant IC1y = 2005790176848670427187600793431377121327396126482966174764938365691826979482;
    
    uint256 constant IC2x = 5335334769047105061867398117476272543850313373056428803572575258562010130926;
    uint256 constant IC2y = 6848130785933199210106035542024224823757968900750176556487820862655172410590;
    
    uint256 constant IC3x = 11024492380308634315741706623553409879844534640943361335439105244136599155364;
    uint256 constant IC3y = 12942788033958994508350400459203853262738494113663532460686760340055929368869;
    
    uint256 constant IC4x = 2362160989635286921926946968955778832697173971856688353849595725032937190611;
    uint256 constant IC4y = 11884381785995126374203966933017949443839760364545810507036013447486836196719;
    
    uint256 constant IC5x = 6078504676230624092428557721232557339202319471836617419108276507345229809067;
    uint256 constant IC5y = 13646440595873595749382981872757470345793119422353975716400328331472103689986;
    
    uint256 constant IC6x = 15748129992328308391119420790447526091514313448445349362868946156570406277563;
    uint256 constant IC6y = 14392479555331550657009384840493219499766814630427675648569538742835282269378;
    
    uint256 constant IC7x = 1545689808619152669103950773138127494874638599577223619229054218189439532690;
    uint256 constant IC7y = 13761614303182088196764966622205692757171053220286896359032992632650609022866;
    
    uint256 constant IC8x = 5618791015038194308257930383673312286536338031319726465585394994502476340932;
    uint256 constant IC8y = 12183981252295674787866818718774878592307319078462155541445452420524026428012;
    
    uint256 constant IC9x = 18466646316504161503262630060516819033537230179872400078972175879290774390328;
    uint256 constant IC9y = 4960204115750441638210896790762084058876467191696107815775632295732240731211;
    
    uint256 constant IC10x = 8896434663563294920604354637786724458606209262478132354919742634589519116876;
    uint256 constant IC10y = 7063441541063708072126056966724343559942517183656752204969386294271757649010;
    
    uint256 constant IC11x = 8315054541154466850470007594007286794329029914761556636134571894117435480393;
    uint256 constant IC11y = 3688883588537884982417927320765136858895524488093088293855528019632335790381;
    
    uint256 constant IC12x = 17250373452626091749551880573059175299731478165888446640169990159783972640920;
    uint256 constant IC12y = 109016652572343827107419351286276481360714860012850562035017650800395175025;
    
    uint256 constant IC13x = 17250477428177426919773515829637160386575429769393040123661131620825747893315;
    uint256 constant IC13y = 15637835286433016441153786106178260661627128168508005934697687867187268004762;
    
    uint256 constant IC14x = 16178547202402144400994814632932627334207301689675568733686466120764798432437;
    uint256 constant IC14y = 2701461181694254834906214135778210451099014778420476649943898026263166974592;
    
    uint256 constant IC15x = 17713800548343449474243094391713930213604503277661696995582740449036409028612;
    uint256 constant IC15y = 8952122245595872073669400222047279276341393423182185502002162194217641975090;
    
    uint256 constant IC16x = 14879722281367526388910445466735646943955889157360436864660833921716112922884;
    uint256 constant IC16y = 14011980434602423961179042189261439168120045633986550514612695766351829949528;
    
    uint256 constant IC17x = 5163117461247021114950496245471631048399056937825843197197513666963301313193;
    uint256 constant IC17y = 5399965252818110085864330004863641149687357479280901887141168822522126777222;
    
    uint256 constant IC18x = 9701128054289991547918106259500222463009334682011266233392961199581923131875;
    uint256 constant IC18y = 14432265151969916541383149504800127636505425269666495979982536742307832690363;
    
    uint256 constant IC19x = 20817353303488425521090771957689395388599022230849541992819199275604767100492;
    uint256 constant IC19y = 1179220894978802381357046229040436961525022304417932153030410886471237968376;
    
    uint256 constant IC20x = 13581074812222259428001506139256144155113642505731941294156571245050895318361;
    uint256 constant IC20y = 2777851071762229454645108405337828833598181658315745772316120155250305912118;
    
    uint256 constant IC21x = 6498114090087573866651425474604979532789618140291972655105215746046324109233;
    uint256 constant IC21y = 10054502002004622510347549908908171176675963093800823192475733559093660167891;
    
    uint256 constant IC22x = 13690387861209747025361078824486108016307554704464350431469261543155043374182;
    uint256 constant IC22y = 8996347178727106552626186998845634868538285404848185880606209398319765055838;
    
    uint256 constant IC23x = 6449260557762003466081184345547186365264203493761247727228098973042266738328;
    uint256 constant IC23y = 649889673031219154571632484858429084885764223154892268633913616234277211675;
    
    uint256 constant IC24x = 15443453426841197524352189764086861360127950094174282446681904439943358532297;
    uint256 constant IC24y = 20573190835358485649124037235454246824339698101418833601304662406122706954081;
    
    uint256 constant IC25x = 18895939434582899792961895222828141900871854043375105991048100260872653409615;
    uint256 constant IC25y = 9864141051855211405883303507951370377649687286820772852601994668420142745996;
    
    uint256 constant IC26x = 16555278145725253624642099335054012499159945502659628947574689758688272586216;
    uint256 constant IC26y = 12975505868757500286329564502661250460056865789353742129229797165324618569322;
    
    uint256 constant IC27x = 6713905206283180092340935915833143512443469044503939701034037132416456812084;
    uint256 constant IC27y = 19211804090035241080670673569169395388032705313186264976757826061699283655097;
    
    uint256 constant IC28x = 13114365788128101454551618317365864402349459071873221010726587388554845505064;
    uint256 constant IC28y = 8721711435986149206200594004902840025107251300039473981628050239778759469949;
    
    uint256 constant IC29x = 19591063165257522868924574850475625580237921568110112139369376485710323394283;
    uint256 constant IC29y = 9368497531379104156950673459774438014221664951605301261441204241783600389058;
    
    uint256 constant IC30x = 17166245383946237694429139500522152991898340210392763268903263352525123577466;
    uint256 constant IC30y = 8991294301348851747880790175039160140695912896225511688421983042392320139699;
    
    uint256 constant IC31x = 12220411731933743213342056453409886980402325373834429280352192506462258809984;
    uint256 constant IC31y = 16199349607943527713297555901049435854591407954601948897421940334370567614838;
    
    uint256 constant IC32x = 11912443722801044528451095140622806925246803035080567290290621932464935488538;
    uint256 constant IC32y = 13806368695987003061889850448186188024522656125942607554225910391369361451719;
    
    uint256 constant IC33x = 12879303124606990910871376358587446361796105673107909675444759309370817588463;
    uint256 constant IC33y = 17089460758899873588192251870087766310003644666256520962542705035958942196510;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[33] calldata _pubSignals) public view returns (bool) {
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
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }

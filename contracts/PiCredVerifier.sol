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
    uint256 constant deltax1 = 17672639955643397971068430230697992423014202005560274200129642163827265403120;
    uint256 constant deltax2 = 15319333835725482285787196522114209483819333382533111301311584308878825620965;
    uint256 constant deltay1 = 7765325015146799027372991324690108705284659850167542541789371365722216323457;
    uint256 constant deltay2 = 4860834081832223325421135299639996358525535830097151075312931321152726727022;

    
    uint256 constant IC0x = 14950821068068122214506343656214122488610657615194508091433504107726646915693;
    uint256 constant IC0y = 11865883835205433378765393289208468056022671490777548846113999941974480878488;
    
    uint256 constant IC1x = 8338087817410481061355802324460822126299971882088274871443161219812042045331;
    uint256 constant IC1y = 4873736057359855626694496477817597408154350511631194443573393715899867716084;
    
    uint256 constant IC2x = 18369465817408864196117609434300305601245276813439566195067013779246033233749;
    uint256 constant IC2y = 1648013449016602344727541489137969736868812557735291298570560697512359614651;
    
    uint256 constant IC3x = 12267071738012183283788460599431244992601690928868959701493986977101405376444;
    uint256 constant IC3y = 21365453705098743686836137185553214734216130856193806150993071563880542766707;
    
    uint256 constant IC4x = 3075936526465986317981217595556860117971709902049986481480757168972024398423;
    uint256 constant IC4y = 16719605005960675031315478035560413951303151541349599761436920476977402601529;
    
    uint256 constant IC5x = 8313691176143437856468013118973154676550654348105463842752307841276290693273;
    uint256 constant IC5y = 21506373389200909730178533102190812013999615505790189849688028103453907916671;
    
    uint256 constant IC6x = 9589928830860054889020791701812860571620303552793650597097582921093794910365;
    uint256 constant IC6y = 12424031274952373665667582569064102565194511589683815420811747857675066336074;
    
    uint256 constant IC7x = 303544101674814215256490598747664394634481375830610929159680753157579585415;
    uint256 constant IC7y = 7986243617482699892701070065542151834522734935407769313801771450738860288396;
    
    uint256 constant IC8x = 2463740769380913219799655354141072522093489882540808449602862329856133295691;
    uint256 constant IC8y = 6009038477102314328347554921022776635028969400738518897147077969437857706848;
    
    uint256 constant IC9x = 15065342625092943017261086088581227005597796880705783250456492642793731146865;
    uint256 constant IC9y = 4649459016932735723524649015963384528695718055056348439163340456425948238600;
    
    uint256 constant IC10x = 16668984351987689763344596999457695623992949310537350907200059906791894733316;
    uint256 constant IC10y = 10309938762300791675749026879548191776340819353232876175893213532695969282720;
    
    uint256 constant IC11x = 12994800478240499712280981939929003289891673997442791654621720113146461444463;
    uint256 constant IC11y = 3399246156618320300666215352796922244948241361710775591155592502470430404973;
    
    uint256 constant IC12x = 157962750209743467847163287081674680746863006557669004163249372097316549782;
    uint256 constant IC12y = 3234002417716918464613286390623789697116389772962537869920753917902181928273;
    
    uint256 constant IC13x = 13566039402321813475536390783670878876276687299121012166017874051280775994894;
    uint256 constant IC13y = 16473544848410291171003224419035412572311749397234660262488295389666342432529;
    
    uint256 constant IC14x = 6924224465807398895465064939478881720020218058749524895817028100502564719538;
    uint256 constant IC14y = 17958956406273698831875755096613375863851258160723759988069459606620791931213;
    
    uint256 constant IC15x = 4536772732413345751383980505863844828607316666718039165724840473981381693092;
    uint256 constant IC15y = 17565503871177612562928786046108487414461575505732363816070497630866925464854;
    
    uint256 constant IC16x = 1502863909611644845769048121858747520624427811441333824866740599834996477348;
    uint256 constant IC16y = 10579090954249513778711410020412154489343040184725591205486894336263911179442;
    
    uint256 constant IC17x = 5631356270495034751962572853680140247486878476951022266634800263281744391736;
    uint256 constant IC17y = 16972099558514528523789190653574207964727963638957468835558846129525359031545;
    
    uint256 constant IC18x = 18787118506083578526095523497002488652086926426093271730622345194964142061027;
    uint256 constant IC18y = 13121796638356871748182504263366100177811801868525552833492043716037555295712;
    
    uint256 constant IC19x = 8441610723387106181082942589143657277232193898866818678527717110590064948470;
    uint256 constant IC19y = 12242348691732813923968354671177927324144343979796858283614281785018249532689;
    
    uint256 constant IC20x = 11899564642284733607522416357343354037980783053667568562589622168742348109526;
    uint256 constant IC20y = 7529246214647218245942149626794556154874616263841812943212534666172339096098;
    
    uint256 constant IC21x = 4340302308658055583513661720042266970466507651884879032583520329613108019149;
    uint256 constant IC21y = 15687115541686614664229413326891003977075488179490348881514714535326299574874;
    
    uint256 constant IC22x = 21155778400287380820092362004234520208692973364995361963299356669943237175300;
    uint256 constant IC22y = 16566889588841725650185853837803164509047115006592690802547642249599077233311;
    
    uint256 constant IC23x = 1749625373526329464710137539685942336418241779939253413582042863179490519330;
    uint256 constant IC23y = 9822830203226354412183017986349384313882906102975599156299797922053435666839;
    
    uint256 constant IC24x = 11488422389449137117754277378089580279647371791593891982452992802465145783809;
    uint256 constant IC24y = 21436715376251217700332907227176483101137586110282080044175050756558333427567;
    
    uint256 constant IC25x = 17594187106594111877629078975257985212567947068360168609966271660322835402340;
    uint256 constant IC25y = 18386823229713658793197058247923961919894663924282216822879722025903132661634;
    
    uint256 constant IC26x = 9839247647460986794765418209236031660489522066649881598593530654010786653920;
    uint256 constant IC26y = 13764480813266716593522277528590492513559066004349855073590956774215061938989;
    
    uint256 constant IC27x = 17002277663548057778912629845998115189112383294767807440951502627019386144270;
    uint256 constant IC27y = 12997921631844058815156999153989704074392749821689538335039208737995168746806;
    
    uint256 constant IC28x = 19598539130577195173600882885079701280941446740840022382419852043781461895455;
    uint256 constant IC28y = 16477471419460750715591971054801993114881040539311299788977221026085344318167;
    
    uint256 constant IC29x = 2730624539845595204315346240111745709987868003810246303488614927473175909547;
    uint256 constant IC29y = 5869058304388600681631264467667869888931166370800579838503723291871038216853;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[29] calldata _pubSignals) public view returns (bool) {
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
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }

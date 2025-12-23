.class public final synthetic Llyiahf/vczjk/eg6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final synthetic OooOOO:I

.field public final synthetic OooOOO0:Llyiahf/vczjk/fg6;

.field public final synthetic OooOOOO:I

.field public final synthetic OooOOOo:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOo:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOo0:Llyiahf/vczjk/ow6;

.field public final synthetic OooOOoo:Llyiahf/vczjk/ow6;

.field public final synthetic OooOo:Llyiahf/vczjk/ow6;

.field public final synthetic OooOo0:Llyiahf/vczjk/hl7;

.field public final synthetic OooOo00:Llyiahf/vczjk/ow6;

.field public final synthetic OooOo0O:Llyiahf/vczjk/ow6;

.field public final synthetic OooOo0o:Llyiahf/vczjk/ow6;

.field public final synthetic OooOoO:F

.field public final synthetic OooOoO0:Llyiahf/vczjk/nf5;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/fg6;IILlyiahf/vczjk/ow6;Llyiahf/vczjk/ow6;Llyiahf/vczjk/ow6;Llyiahf/vczjk/ow6;Llyiahf/vczjk/ow6;Llyiahf/vczjk/hl7;Llyiahf/vczjk/ow6;Llyiahf/vczjk/ow6;Llyiahf/vczjk/ow6;Llyiahf/vczjk/nf5;F)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/eg6;->OooOOO0:Llyiahf/vczjk/fg6;

    iput p2, p0, Llyiahf/vczjk/eg6;->OooOOO:I

    iput p3, p0, Llyiahf/vczjk/eg6;->OooOOOO:I

    iput-object p4, p0, Llyiahf/vczjk/eg6;->OooOOOo:Llyiahf/vczjk/ow6;

    iput-object p5, p0, Llyiahf/vczjk/eg6;->OooOOo0:Llyiahf/vczjk/ow6;

    iput-object p6, p0, Llyiahf/vczjk/eg6;->OooOOo:Llyiahf/vczjk/ow6;

    iput-object p7, p0, Llyiahf/vczjk/eg6;->OooOOoo:Llyiahf/vczjk/ow6;

    iput-object p8, p0, Llyiahf/vczjk/eg6;->OooOo00:Llyiahf/vczjk/ow6;

    iput-object p9, p0, Llyiahf/vczjk/eg6;->OooOo0:Llyiahf/vczjk/hl7;

    iput-object p10, p0, Llyiahf/vczjk/eg6;->OooOo0O:Llyiahf/vczjk/ow6;

    iput-object p11, p0, Llyiahf/vczjk/eg6;->OooOo0o:Llyiahf/vczjk/ow6;

    iput-object p12, p0, Llyiahf/vczjk/eg6;->OooOo:Llyiahf/vczjk/ow6;

    iput-object p13, p0, Llyiahf/vczjk/eg6;->OooOoO0:Llyiahf/vczjk/nf5;

    iput p14, p0, Llyiahf/vczjk/eg6;->OooOoO:F

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 23

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    check-cast v1, Llyiahf/vczjk/nw6;

    iget-object v2, v0, Llyiahf/vczjk/eg6;->OooOo0:Llyiahf/vczjk/hl7;

    iget-object v2, v2, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    move-object v7, v2

    check-cast v7, Llyiahf/vczjk/ow6;

    iget-object v2, v0, Llyiahf/vczjk/eg6;->OooOoO0:Llyiahf/vczjk/nf5;

    invoke-interface {v2}, Llyiahf/vczjk/f62;->OooO0O0()F

    move-result v3

    invoke-interface {v2}, Llyiahf/vczjk/o34;->getLayoutDirection()Llyiahf/vczjk/yn4;

    move-result-object v4

    iget-object v5, v0, Llyiahf/vczjk/eg6;->OooOOO0:Llyiahf/vczjk/fg6;

    iget v6, v5, Llyiahf/vczjk/fg6;->OooO0o0:F

    invoke-interface {v2, v6}, Llyiahf/vczjk/f62;->Ooooo00(F)F

    move-result v2

    iget-object v6, v0, Llyiahf/vczjk/eg6;->OooOo0o:Llyiahf/vczjk/ow6;

    const/4 v9, 0x0

    move v8, v3

    const/4 v3, 0x0

    invoke-static {v1, v6, v9, v3}, Llyiahf/vczjk/nw6;->OooO0o(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    iget-object v10, v0, Llyiahf/vczjk/eg6;->OooOo:Llyiahf/vczjk/ow6;

    if-eqz v10, :cond_0

    iget v6, v10, Llyiahf/vczjk/ow6;->OooOOO:I

    goto :goto_0

    :cond_0
    move v6, v9

    :goto_0
    iget v11, v0, Llyiahf/vczjk/eg6;->OooOOO:I

    sub-int/2addr v11, v6

    iget-object v6, v5, Llyiahf/vczjk/fg6;->OooO0Oo:Llyiahf/vczjk/di6;

    iget v12, v6, Llyiahf/vczjk/di6;->OooO0O0:F

    mul-float/2addr v12, v8

    invoke-static {v12}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v12

    iget-object v14, v0, Llyiahf/vczjk/eg6;->OooOOOo:Llyiahf/vczjk/ow6;

    const/4 v15, 0x1

    const/high16 v16, 0x40000000    # 2.0f

    if-eqz v14, :cond_1

    iget v3, v14, Llyiahf/vczjk/ow6;->OooOOO:I

    sub-int v3, v11, v3

    int-to-float v3, v3

    div-float v3, v3, v16

    const/16 v17, 0x0

    int-to-float v13, v15

    add-float v13, v13, v17

    mul-float/2addr v13, v3

    invoke-static {v13}, Ljava/lang/Math;->round(F)I

    move-result v3

    invoke-static {v1, v14, v9, v3}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    goto :goto_1

    :cond_1
    const/16 v17, 0x0

    :goto_1
    iget v13, v0, Llyiahf/vczjk/eg6;->OooOOOO:I

    iget-object v3, v0, Llyiahf/vczjk/eg6;->OooOOo0:Llyiahf/vczjk/ow6;

    if-eqz v7, :cond_8

    iget v9, v7, Llyiahf/vczjk/ow6;->OooOOO:I

    div-int/lit8 v9, v9, 0x2

    neg-int v9, v9

    iget v15, v0, Llyiahf/vczjk/eg6;->OooOoO:F

    invoke-static {v12, v15, v9}, Llyiahf/vczjk/so8;->Oooo00o(IFI)I

    move-result v9

    move/from16 v18, v2

    iget-object v2, v5, Llyiahf/vczjk/fg6;->OooO0O0:Llyiahf/vczjk/fj9;

    invoke-static {v6, v4}, Landroidx/compose/foundation/layout/OooO00o;->OooO0o(Llyiahf/vczjk/bi6;Llyiahf/vczjk/yn4;)F

    move-result v19

    mul-float v19, v19, v8

    invoke-static {v6, v4}, Landroidx/compose/foundation/layout/OooO00o;->OooO0o0(Llyiahf/vczjk/bi6;Llyiahf/vczjk/yn4;)F

    move-result v6

    mul-float/2addr v6, v8

    if-nez v14, :cond_2

    move/from16 v8, v19

    goto :goto_2

    :cond_2
    iget v8, v14, Llyiahf/vczjk/ow6;->OooOOO0:I

    int-to-float v8, v8

    sub-float v20, v19, v18

    cmpg-float v21, v20, v17

    if-gez v21, :cond_3

    move/from16 v20, v17

    :cond_3
    add-float v8, v8, v20

    :goto_2
    if-nez v3, :cond_4

    move-object/from16 v20, v5

    move v5, v6

    :goto_3
    move-object/from16 v18, v3

    goto :goto_4

    :cond_4
    move-object/from16 v20, v5

    iget v5, v3, Llyiahf/vczjk/ow6;->OooOOO0:I

    int-to-float v5, v5

    sub-float v18, v6, v18

    cmpg-float v21, v18, v17

    if-gez v21, :cond_5

    move/from16 v18, v17

    :cond_5
    add-float v5, v5, v18

    goto :goto_3

    :goto_4
    sget-object v3, Llyiahf/vczjk/yn4;->OooOOO0:Llyiahf/vczjk/yn4;

    if-ne v4, v3, :cond_6

    move/from16 v21, v19

    goto :goto_5

    :cond_6
    move/from16 v21, v6

    :goto_5
    if-ne v4, v3, :cond_7

    move v3, v8

    goto :goto_6

    :cond_7
    move v3, v5

    :goto_6
    sget v22, Llyiahf/vczjk/wi9;->OooO00o:F

    move/from16 v22, v3

    iget v3, v7, Llyiahf/vczjk/ow6;->OooOOO0:I

    add-float/2addr v8, v5

    invoke-static {v8}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v5

    sub-int v5, v13, v5

    iget-object v8, v2, Llyiahf/vczjk/fj9;->OooO0O0:Llyiahf/vczjk/sb0;

    invoke-virtual {v8, v3, v5, v4}, Llyiahf/vczjk/sb0;->OooO00o(IILlyiahf/vczjk/yn4;)I

    move-result v3

    int-to-float v3, v3

    add-float v3, v3, v22

    invoke-static {v2}, Llyiahf/vczjk/wi9;->OooO0Oo(Llyiahf/vczjk/fj9;)Llyiahf/vczjk/m4;

    move-result-object v2

    iget v5, v7, Llyiahf/vczjk/ow6;->OooOOO0:I

    add-float v19, v19, v6

    invoke-static/range {v19 .. v19}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v6

    sub-int v6, v13, v6

    check-cast v2, Llyiahf/vczjk/sb0;

    invoke-virtual {v2, v5, v6, v4}, Llyiahf/vczjk/sb0;->OooO00o(IILlyiahf/vczjk/yn4;)I

    move-result v2

    int-to-float v2, v2

    add-float v2, v2, v21

    invoke-static {v3, v2, v15}, Llyiahf/vczjk/so8;->Oooo00O(FFF)F

    move-result v2

    invoke-static {v2}, Llyiahf/vczjk/ye5;->Oooo000(F)I

    move-result v2

    move/from16 v3, v17

    invoke-virtual {v1, v7, v2, v9, v3}, Llyiahf/vczjk/nw6;->OooO0o0(Llyiahf/vczjk/ow6;IIF)V

    goto :goto_7

    :cond_8
    move-object/from16 v18, v3

    move-object/from16 v20, v5

    :goto_7
    iget-object v8, v0, Llyiahf/vczjk/eg6;->OooOOo:Llyiahf/vczjk/ow6;

    if-eqz v8, :cond_a

    if-eqz v14, :cond_9

    iget v2, v14, Llyiahf/vczjk/ow6;->OooOOO0:I

    :goto_8
    move v5, v11

    move v6, v12

    move-object/from16 v9, v18

    move-object/from16 v4, v20

    const/4 v3, 0x0

    goto :goto_9

    :cond_9
    const/4 v2, 0x0

    goto :goto_8

    :goto_9
    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/fg6;->OooO0oo(ILlyiahf/vczjk/fg6;IILlyiahf/vczjk/ow6;Llyiahf/vczjk/ow6;)I

    move-result v11

    invoke-static {v1, v8, v2, v11}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    goto :goto_a

    :cond_a
    move v5, v11

    move v6, v12

    move-object/from16 v9, v18

    move-object/from16 v4, v20

    const/4 v3, 0x0

    :goto_a
    if-eqz v14, :cond_b

    iget v2, v14, Llyiahf/vczjk/ow6;->OooOOO0:I

    goto :goto_b

    :cond_b
    const/4 v2, 0x0

    :goto_b
    if-eqz v8, :cond_c

    iget v8, v8, Llyiahf/vczjk/ow6;->OooOOO0:I

    goto :goto_c

    :cond_c
    const/4 v8, 0x0

    :goto_c
    add-int/2addr v2, v8

    iget-object v8, v0, Llyiahf/vczjk/eg6;->OooOo00:Llyiahf/vczjk/ow6;

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/fg6;->OooO0oo(ILlyiahf/vczjk/fg6;IILlyiahf/vczjk/ow6;Llyiahf/vczjk/ow6;)I

    move-result v11

    invoke-static {v1, v8, v2, v11}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    iget-object v8, v0, Llyiahf/vczjk/eg6;->OooOo0O:Llyiahf/vczjk/ow6;

    if-eqz v8, :cond_d

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/fg6;->OooO0oo(ILlyiahf/vczjk/fg6;IILlyiahf/vczjk/ow6;Llyiahf/vczjk/ow6;)I

    move-result v11

    invoke-static {v1, v8, v2, v11}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    :cond_d
    iget-object v8, v0, Llyiahf/vczjk/eg6;->OooOOoo:Llyiahf/vczjk/ow6;

    if-eqz v8, :cond_f

    if-eqz v9, :cond_e

    iget v2, v9, Llyiahf/vczjk/ow6;->OooOOO0:I

    goto :goto_d

    :cond_e
    const/4 v2, 0x0

    :goto_d
    sub-int v2, v13, v2

    iget v11, v8, Llyiahf/vczjk/ow6;->OooOOO0:I

    sub-int/2addr v2, v11

    invoke-static/range {v3 .. v8}, Llyiahf/vczjk/fg6;->OooO0oo(ILlyiahf/vczjk/fg6;IILlyiahf/vczjk/ow6;Llyiahf/vczjk/ow6;)I

    move-result v3

    invoke-static {v1, v8, v2, v3}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    :cond_f
    if-eqz v9, :cond_10

    iget v2, v9, Llyiahf/vczjk/ow6;->OooOOO0:I

    sub-int/2addr v13, v2

    iget v2, v9, Llyiahf/vczjk/ow6;->OooOOO:I

    sub-int v11, v5, v2

    int-to-float v2, v11

    div-float v2, v2, v16

    const/4 v3, 0x1

    int-to-float v3, v3

    const/16 v17, 0x0

    add-float v3, v3, v17

    mul-float/2addr v3, v2

    invoke-static {v3}, Ljava/lang/Math;->round(F)I

    move-result v2

    invoke-static {v1, v9, v13, v2}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    :cond_10
    if-eqz v10, :cond_11

    const/4 v2, 0x0

    invoke-static {v1, v10, v2, v5}, Llyiahf/vczjk/nw6;->OooO0oo(Llyiahf/vczjk/nw6;Llyiahf/vczjk/ow6;II)V

    :cond_11
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method

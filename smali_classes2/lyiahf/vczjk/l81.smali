.class public final Llyiahf/vczjk/l81;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO0:Z


# direct methods
.method public constructor <init>(Z)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/l81;->OooOOO0:Z

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    move-object/from16 v3, p1

    check-cast v3, Llyiahf/vczjk/rf1;

    move-object/from16 v0, p2

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    move-result v0

    and-int/lit8 v0, v0, 0x3

    const/4 v1, 0x2

    if-ne v0, v1, :cond_0

    move-object v0, v3

    check-cast v0, Llyiahf/vczjk/zf1;

    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v1

    if-nez v1, :cond_1

    :cond_0
    move-object/from16 v8, p0

    goto :goto_0

    :cond_1
    invoke-virtual {v0}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    move-object/from16 v8, p0

    goto/16 :goto_5

    :goto_0
    iget-boolean v0, v8, Llyiahf/vczjk/l81;->OooOOO0:Z

    const/4 v6, 0x0

    if-eqz v0, :cond_2

    const/high16 v0, 0x43340000    # 180.0f

    goto :goto_1

    :cond_2
    move v0, v6

    :goto_1
    const/4 v4, 0x0

    const/16 v5, 0x1e

    const/4 v1, 0x0

    const/4 v2, 0x0

    invoke-static/range {v0 .. v5}, Llyiahf/vczjk/ti;->OooO0O0(FLlyiahf/vczjk/p13;Ljava/lang/String;Llyiahf/vczjk/rf1;II)Llyiahf/vczjk/p29;

    move-result-object v0

    sget-object v9, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v14

    cmpg-float v0, v14, v6

    if-nez v0, :cond_3

    :goto_2
    move-object v2, v9

    goto :goto_3

    :cond_3
    const/4 v15, 0x0

    const/16 v16, 0x0

    const/4 v10, 0x0

    const/4 v11, 0x0

    const/4 v12, 0x0

    const/4 v13, 0x0

    const v17, 0x1feff

    invoke-static/range {v9 .. v17}, Landroidx/compose/ui/graphics/OooO00o;->OooO0O0(Llyiahf/vczjk/kl5;FFFFFLlyiahf/vczjk/qj8;ZI)Llyiahf/vczjk/kl5;

    move-result-object v9

    goto :goto_2

    :goto_3
    sget-object v0, Llyiahf/vczjk/r02;->OooOOO0:Llyiahf/vczjk/qv3;

    if-eqz v0, :cond_4

    goto :goto_4

    :cond_4
    new-instance v9, Llyiahf/vczjk/pv3;

    const/16 v17, 0x0

    const/16 v18, 0x0

    const-string v10, "Outlined.ArrowDropDown"

    const/high16 v11, 0x41c00000    # 24.0f

    const/high16 v12, 0x41c00000    # 24.0f

    const/high16 v13, 0x41c00000    # 24.0f

    const/high16 v14, 0x41c00000    # 24.0f

    const-wide/16 v15, 0x0

    const/16 v19, 0x60

    invoke-direct/range {v9 .. v19}, Llyiahf/vczjk/pv3;-><init>(Ljava/lang/String;FFFFJIZI)V

    sget v0, Llyiahf/vczjk/tda;->OooO00o:I

    new-instance v0, Llyiahf/vczjk/gx8;

    sget-wide v4, Llyiahf/vczjk/n21;->OooO0O0:J

    invoke-direct {v0, v4, v5}, Llyiahf/vczjk/gx8;-><init>(J)V

    new-instance v1, Ljava/util/ArrayList;

    const/16 v4, 0x20

    invoke-direct {v1, v4}, Ljava/util/ArrayList;-><init>(I)V

    new-instance v4, Llyiahf/vczjk/lq6;

    const/high16 v5, 0x41200000    # 10.0f

    const/high16 v6, 0x40e00000    # 7.0f

    invoke-direct {v4, v6, v5}, Llyiahf/vczjk/lq6;-><init>(FF)V

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v4, Llyiahf/vczjk/sq6;

    const/high16 v5, 0x40a00000    # 5.0f

    invoke-direct {v4, v5, v5}, Llyiahf/vczjk/sq6;-><init>(FF)V

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v4, Llyiahf/vczjk/sq6;

    const/high16 v7, -0x3f600000    # -5.0f

    invoke-direct {v4, v5, v7}, Llyiahf/vczjk/sq6;-><init>(FF)V

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    new-instance v4, Llyiahf/vczjk/jq6;

    invoke-direct {v4, v6}, Llyiahf/vczjk/jq6;-><init>(F)V

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    sget-object v4, Llyiahf/vczjk/hq6;->OooO0OO:Llyiahf/vczjk/hq6;

    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    invoke-static {v9, v1, v0}, Llyiahf/vczjk/pv3;->OooO00o(Llyiahf/vczjk/pv3;Ljava/util/ArrayList;Llyiahf/vczjk/gx8;)V

    invoke-virtual {v9}, Llyiahf/vczjk/pv3;->OooO0O0()Llyiahf/vczjk/qv3;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/r02;->OooOOO0:Llyiahf/vczjk/qv3;

    :goto_4
    const/16 v6, 0x30

    const/16 v7, 0x8

    const-string v1, "Info"

    move-object v5, v3

    const-wide/16 v3, 0x0

    invoke-static/range {v0 .. v7}, Llyiahf/vczjk/yt3;->OooO00o(Llyiahf/vczjk/qv3;Ljava/lang/String;Llyiahf/vczjk/kl5;JLlyiahf/vczjk/rf1;II)V

    :goto_5
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method

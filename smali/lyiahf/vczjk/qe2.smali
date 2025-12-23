.class public final Llyiahf/vczjk/qe2;
.super Llyiahf/vczjk/rs7;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $currentDown:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field final synthetic $deepPress:Llyiahf/vczjk/dl7;

.field final synthetic $longPress:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field I$0:I

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dl7;Llyiahf/vczjk/hl7;Llyiahf/vczjk/hl7;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/qe2;->$deepPress:Llyiahf/vczjk/dl7;

    iput-object p2, p0, Llyiahf/vczjk/qe2;->$currentDown:Llyiahf/vczjk/hl7;

    iput-object p3, p0, Llyiahf/vczjk/qe2;->$longPress:Llyiahf/vczjk/hl7;

    invoke-direct {p0, p4}, Llyiahf/vczjk/rs7;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 4

    new-instance v0, Llyiahf/vczjk/qe2;

    iget-object v1, p0, Llyiahf/vczjk/qe2;->$deepPress:Llyiahf/vczjk/dl7;

    iget-object v2, p0, Llyiahf/vczjk/qe2;->$currentDown:Llyiahf/vczjk/hl7;

    iget-object v3, p0, Llyiahf/vczjk/qe2;->$longPress:Llyiahf/vczjk/hl7;

    invoke-direct {v0, v1, v2, v3, p2}, Llyiahf/vczjk/qe2;-><init>(Llyiahf/vczjk/dl7;Llyiahf/vczjk/hl7;Llyiahf/vczjk/hl7;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/qe2;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/kb9;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/qe2;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/qe2;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/qe2;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v0, p0

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/qe2;->label:I

    const/4 v3, 0x1

    const/4 v4, 0x2

    const/4 v5, 0x0

    if-eqz v2, :cond_2

    if-eq v2, v3, :cond_1

    if-ne v2, v4, :cond_0

    iget v2, v0, Llyiahf/vczjk/qe2;->I$0:I

    iget-object v7, v0, Llyiahf/vczjk/qe2;->L$1:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/ey6;

    iget-object v8, v0, Llyiahf/vczjk/qe2;->L$0:Ljava/lang/Object;

    check-cast v8, Llyiahf/vczjk/kb9;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v5, p1

    goto/16 :goto_7

    :cond_0
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_1
    iget v2, v0, Llyiahf/vczjk/qe2;->I$0:I

    iget-object v7, v0, Llyiahf/vczjk/qe2;->L$0:Ljava/lang/Object;

    check-cast v7, Llyiahf/vczjk/kb9;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v8, p1

    goto :goto_1

    :cond_2
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v2, v0, Llyiahf/vczjk/qe2;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/kb9;

    move-object v7, v2

    const/4 v2, 0x0

    :goto_0
    if-nez v2, :cond_13

    sget-object v8, Llyiahf/vczjk/fy6;->OooOOO:Llyiahf/vczjk/fy6;

    iput-object v7, v0, Llyiahf/vczjk/qe2;->L$0:Ljava/lang/Object;

    iput-object v5, v0, Llyiahf/vczjk/qe2;->L$1:Ljava/lang/Object;

    iput v2, v0, Llyiahf/vczjk/qe2;->I$0:I

    iput v3, v0, Llyiahf/vczjk/qe2;->label:I

    invoke-virtual {v7, v8, v0}, Llyiahf/vczjk/kb9;->OooO00o(Llyiahf/vczjk/fy6;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object v8

    if-ne v8, v1, :cond_3

    goto :goto_6

    :cond_3
    :goto_1
    check-cast v8, Llyiahf/vczjk/ey6;

    iget-object v9, v8, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    invoke-interface {v9}, Ljava/util/Collection;->size()I

    move-result v10

    const/4 v11, 0x0

    :goto_2
    if-ge v11, v10, :cond_5

    invoke-interface {v9, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/ky6;

    invoke-static {v12}, Llyiahf/vczjk/vl6;->OooOO0(Llyiahf/vczjk/ky6;)Z

    move-result v12

    if-nez v12, :cond_4

    goto :goto_3

    :cond_4
    add-int/lit8 v11, v11, 0x1

    goto :goto_2

    :cond_5
    move v2, v3

    :goto_3
    iget-object v9, v8, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    invoke-interface {v9}, Ljava/util/Collection;->size()I

    move-result v10

    const/4 v11, 0x0

    :goto_4
    if-ge v11, v10, :cond_8

    invoke-interface {v9, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/ky6;

    invoke-virtual {v12}, Llyiahf/vczjk/ky6;->OooO0O0()Z

    move-result v13

    if-nez v13, :cond_7

    iget-object v13, v7, Llyiahf/vczjk/kb9;->OooOOo:Llyiahf/vczjk/nb9;

    iget-wide v13, v13, Llyiahf/vczjk/nb9;->Oooo0O0:J

    invoke-virtual {v7}, Llyiahf/vczjk/kb9;->OooO0OO()J

    move-result-wide v5

    invoke-static {v12, v13, v14, v5, v6}, Llyiahf/vczjk/vl6;->OooOOoo(Llyiahf/vczjk/ky6;JJ)Z

    move-result v5

    if-eqz v5, :cond_6

    goto :goto_5

    :cond_6
    add-int/lit8 v11, v11, 0x1

    const/4 v5, 0x0

    goto :goto_4

    :cond_7
    :goto_5
    move v2, v3

    :cond_8
    invoke-static {v8}, Llyiahf/vczjk/xr6;->OooOOO0(Llyiahf/vczjk/ey6;)Z

    move-result v5

    if-eqz v5, :cond_9

    iget-object v2, v0, Llyiahf/vczjk/qe2;->$deepPress:Llyiahf/vczjk/dl7;

    iput-boolean v3, v2, Llyiahf/vczjk/dl7;->element:Z

    move v2, v3

    :cond_9
    sget-object v5, Llyiahf/vczjk/fy6;->OooOOOO:Llyiahf/vczjk/fy6;

    iput-object v7, v0, Llyiahf/vczjk/qe2;->L$0:Ljava/lang/Object;

    iput-object v8, v0, Llyiahf/vczjk/qe2;->L$1:Ljava/lang/Object;

    iput v2, v0, Llyiahf/vczjk/qe2;->I$0:I

    iput v4, v0, Llyiahf/vczjk/qe2;->label:I

    invoke-virtual {v7, v5, v0}, Llyiahf/vczjk/kb9;->OooO00o(Llyiahf/vczjk/fy6;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object v5

    if-ne v5, v1, :cond_a

    :goto_6
    return-object v1

    :cond_a
    move-object v15, v8

    move-object v8, v7

    move-object v7, v15

    :goto_7
    check-cast v5, Llyiahf/vczjk/ey6;

    iget-object v5, v5, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    invoke-interface {v5}, Ljava/util/Collection;->size()I

    move-result v6

    const/4 v9, 0x0

    :goto_8
    if-ge v9, v6, :cond_c

    invoke-interface {v5, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/ky6;

    invoke-virtual {v10}, Llyiahf/vczjk/ky6;->OooO0O0()Z

    move-result v10

    if-eqz v10, :cond_b

    move v2, v3

    goto :goto_9

    :cond_b
    add-int/lit8 v9, v9, 0x1

    goto :goto_8

    :cond_c
    :goto_9
    iget-object v5, v0, Llyiahf/vczjk/qe2;->$currentDown:Llyiahf/vczjk/hl7;

    iget-object v5, v5, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/ky6;

    iget-wide v5, v5, Llyiahf/vczjk/ky6;->OooO00o:J

    invoke-static {v7, v5, v6}, Llyiahf/vczjk/ve2;->OooO0Oo(Llyiahf/vczjk/ey6;J)Z

    move-result v5

    iget-object v6, v7, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    if-eqz v5, :cond_10

    invoke-interface {v6}, Ljava/util/Collection;->size()I

    move-result v5

    const/4 v7, 0x0

    :goto_a
    if-ge v7, v5, :cond_e

    invoke-interface {v6, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v9

    move-object v10, v9

    check-cast v10, Llyiahf/vczjk/ky6;

    iget-boolean v10, v10, Llyiahf/vczjk/ky6;->OooO0Oo:Z

    if-eqz v10, :cond_d

    goto :goto_b

    :cond_d
    add-int/lit8 v7, v7, 0x1

    goto :goto_a

    :cond_e
    const/4 v9, 0x0

    :goto_b
    check-cast v9, Llyiahf/vczjk/ky6;

    if-eqz v9, :cond_f

    iget-object v5, v0, Llyiahf/vczjk/qe2;->$currentDown:Llyiahf/vczjk/hl7;

    iput-object v9, v5, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    iget-object v5, v0, Llyiahf/vczjk/qe2;->$longPress:Llyiahf/vczjk/hl7;

    iput-object v9, v5, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    goto :goto_f

    :cond_f
    move v2, v3

    move-object v7, v8

    :goto_c
    const/4 v5, 0x0

    goto/16 :goto_0

    :cond_10
    iget-object v5, v0, Llyiahf/vczjk/qe2;->$longPress:Llyiahf/vczjk/hl7;

    iget-object v7, v0, Llyiahf/vczjk/qe2;->$currentDown:Llyiahf/vczjk/hl7;

    invoke-interface {v6}, Ljava/util/Collection;->size()I

    move-result v9

    const/4 v10, 0x0

    :goto_d
    if-ge v10, v9, :cond_12

    invoke-interface {v6, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v11

    move-object v12, v11

    check-cast v12, Llyiahf/vczjk/ky6;

    iget-wide v12, v12, Llyiahf/vczjk/ky6;->OooO00o:J

    iget-object v14, v7, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast v14, Llyiahf/vczjk/ky6;

    iget-wide v3, v14, Llyiahf/vczjk/ky6;->OooO00o:J

    invoke-static {v12, v13, v3, v4}, Llyiahf/vczjk/tn6;->OooO0oo(JJ)Z

    move-result v3

    if-eqz v3, :cond_11

    goto :goto_e

    :cond_11
    add-int/lit8 v10, v10, 0x1

    const/4 v3, 0x1

    const/4 v4, 0x2

    goto :goto_d

    :cond_12
    const/4 v11, 0x0

    :goto_e
    iput-object v11, v5, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    :goto_f
    move-object v7, v8

    const/4 v3, 0x1

    const/4 v4, 0x2

    goto :goto_c

    :cond_13
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method

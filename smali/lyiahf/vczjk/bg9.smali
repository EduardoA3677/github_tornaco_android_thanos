.class public final Llyiahf/vczjk/bg9;
.super Llyiahf/vczjk/rs7;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $pass:Llyiahf/vczjk/fy6;

.field final synthetic $result:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/fy6;Llyiahf/vczjk/hl7;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/bg9;->$pass:Llyiahf/vczjk/fy6;

    iput-object p2, p0, Llyiahf/vczjk/bg9;->$result:Llyiahf/vczjk/hl7;

    invoke-direct {p0, p3}, Llyiahf/vczjk/rs7;-><init>(Llyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/bg9;

    iget-object v1, p0, Llyiahf/vczjk/bg9;->$pass:Llyiahf/vczjk/fy6;

    iget-object v2, p0, Llyiahf/vczjk/bg9;->$result:Llyiahf/vczjk/hl7;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/bg9;-><init>(Llyiahf/vczjk/fy6;Llyiahf/vczjk/hl7;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/bg9;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/kb9;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/bg9;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/bg9;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bg9;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v0, p0

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/bg9;->label:I

    sget-object v3, Llyiahf/vczjk/v55;->OooO00o:Llyiahf/vczjk/v55;

    const/4 v4, 0x1

    const/4 v5, 0x2

    const/4 v6, 0x0

    if-eqz v2, :cond_2

    if-eq v2, v4, :cond_1

    if-ne v2, v5, :cond_0

    iget-object v2, v0, Llyiahf/vczjk/bg9;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/kb9;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v7, p1

    goto/16 :goto_5

    :cond_0
    new-instance v1, Ljava/lang/IllegalStateException;

    const-string v2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v1, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v1

    :cond_1
    iget-object v2, v0, Llyiahf/vczjk/bg9;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/kb9;

    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v7, p1

    goto :goto_0

    :cond_2
    invoke-static/range {p1 .. p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object v2, v0, Llyiahf/vczjk/bg9;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/kb9;

    :cond_3
    iget-object v7, v0, Llyiahf/vczjk/bg9;->$pass:Llyiahf/vczjk/fy6;

    iput-object v2, v0, Llyiahf/vczjk/bg9;->L$0:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/bg9;->label:I

    invoke-virtual {v2, v7, v0}, Llyiahf/vczjk/kb9;->OooO00o(Llyiahf/vczjk/fy6;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object v7

    if-ne v7, v1, :cond_4

    goto :goto_4

    :cond_4
    :goto_0
    check-cast v7, Llyiahf/vczjk/ey6;

    iget-object v8, v7, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    invoke-interface {v8}, Ljava/util/Collection;->size()I

    move-result v9

    move v10, v6

    :goto_1
    iget-object v11, v7, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    if-ge v10, v9, :cond_c

    invoke-interface {v8, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v12

    check-cast v12, Llyiahf/vczjk/ky6;

    invoke-static {v12}, Llyiahf/vczjk/vl6;->OooO(Llyiahf/vczjk/ky6;)Z

    move-result v12

    if-nez v12, :cond_b

    invoke-static {v7}, Llyiahf/vczjk/xr6;->OooOOO0(Llyiahf/vczjk/ey6;)Z

    move-result v7

    if-eqz v7, :cond_5

    iget-object v1, v0, Llyiahf/vczjk/bg9;->$result:Llyiahf/vczjk/hl7;

    sget-object v2, Llyiahf/vczjk/x55;->OooO00o:Llyiahf/vczjk/x55;

    iput-object v2, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    goto/16 :goto_7

    :cond_5
    invoke-interface {v11}, Ljava/util/Collection;->size()I

    move-result v7

    move v8, v6

    :goto_2
    if-ge v8, v7, :cond_8

    invoke-interface {v11, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v9

    check-cast v9, Llyiahf/vczjk/ky6;

    invoke-virtual {v9}, Llyiahf/vczjk/ky6;->OooO0O0()Z

    move-result v10

    if-nez v10, :cond_7

    iget-object v10, v2, Llyiahf/vczjk/kb9;->OooOOo:Llyiahf/vczjk/nb9;

    iget-wide v12, v10, Llyiahf/vczjk/nb9;->Oooo0O0:J

    invoke-virtual {v2}, Llyiahf/vczjk/kb9;->OooO0OO()J

    move-result-wide v14

    invoke-static {v9, v12, v13, v14, v15}, Llyiahf/vczjk/vl6;->OooOOoo(Llyiahf/vczjk/ky6;JJ)Z

    move-result v9

    if-eqz v9, :cond_6

    goto :goto_3

    :cond_6
    add-int/lit8 v8, v8, 0x1

    goto :goto_2

    :cond_7
    :goto_3
    iget-object v1, v0, Llyiahf/vczjk/bg9;->$result:Llyiahf/vczjk/hl7;

    iput-object v3, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    goto :goto_7

    :cond_8
    sget-object v7, Llyiahf/vczjk/fy6;->OooOOOO:Llyiahf/vczjk/fy6;

    iput-object v2, v0, Llyiahf/vczjk/bg9;->L$0:Ljava/lang/Object;

    iput v5, v0, Llyiahf/vczjk/bg9;->label:I

    invoke-virtual {v2, v7, v0}, Llyiahf/vczjk/kb9;->OooO00o(Llyiahf/vczjk/fy6;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object v7

    if-ne v7, v1, :cond_9

    :goto_4
    return-object v1

    :cond_9
    :goto_5
    check-cast v7, Llyiahf/vczjk/ey6;

    iget-object v7, v7, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    invoke-interface {v7}, Ljava/util/Collection;->size()I

    move-result v8

    move v9, v6

    :goto_6
    if-ge v9, v8, :cond_3

    invoke-interface {v7, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Llyiahf/vczjk/ky6;

    invoke-virtual {v10}, Llyiahf/vczjk/ky6;->OooO0O0()Z

    move-result v10

    if-eqz v10, :cond_a

    iget-object v1, v0, Llyiahf/vczjk/bg9;->$result:Llyiahf/vczjk/hl7;

    iput-object v3, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    goto :goto_7

    :cond_a
    add-int/lit8 v9, v9, 0x1

    goto :goto_6

    :cond_b
    add-int/lit8 v10, v10, 0x1

    goto :goto_1

    :cond_c
    iget-object v1, v0, Llyiahf/vczjk/bg9;->$result:Llyiahf/vczjk/hl7;

    new-instance v2, Llyiahf/vczjk/w55;

    invoke-interface {v11, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Llyiahf/vczjk/ky6;

    invoke-direct {v2, v3}, Llyiahf/vczjk/w55;-><init>(Llyiahf/vczjk/ky6;)V

    iput-object v2, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    :goto_7
    sget-object v1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v1
.end method

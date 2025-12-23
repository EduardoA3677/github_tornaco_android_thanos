.class public abstract Llyiahf/vczjk/ve2;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:F


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const-wide/high16 v0, 0x3fc0000000000000L    # 0.125

    double-to-float v0, v0

    const/16 v1, 0x12

    int-to-float v1, v1

    div-float/2addr v0, v1

    sput v0, Llyiahf/vczjk/ve2;->OooO00o:F

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/kb9;JLlyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 17

    move-wide/from16 v0, p1

    move-object/from16 v2, p3

    instance-of v3, v2, Llyiahf/vczjk/oe2;

    if-eqz v3, :cond_0

    move-object v3, v2

    check-cast v3, Llyiahf/vczjk/oe2;

    iget v4, v3, Llyiahf/vczjk/oe2;->label:I

    const/high16 v5, -0x80000000

    and-int v6, v4, v5

    if-eqz v6, :cond_0

    sub-int/2addr v4, v5

    iput v4, v3, Llyiahf/vczjk/oe2;->label:I

    goto :goto_0

    :cond_0
    new-instance v3, Llyiahf/vczjk/oe2;

    invoke-direct {v3, v2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object v2, v3, Llyiahf/vczjk/oe2;->result:Ljava/lang/Object;

    sget-object v4, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v5, v3, Llyiahf/vczjk/oe2;->label:I

    const/4 v6, 0x1

    const/4 v7, 0x0

    if-eqz v5, :cond_2

    if-ne v5, v6, :cond_1

    iget-object v0, v3, Llyiahf/vczjk/oe2;->L$1:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/gl7;

    iget-object v1, v3, Llyiahf/vczjk/oe2;->L$0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/kb9;

    invoke-static {v2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_2
    invoke-static {v2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object/from16 v2, p0

    iget-object v5, v2, Llyiahf/vczjk/kb9;->OooOOo:Llyiahf/vczjk/nb9;

    iget-object v5, v5, Llyiahf/vczjk/nb9;->OooOooo:Llyiahf/vczjk/ey6;

    invoke-static {v5, v0, v1}, Llyiahf/vczjk/ve2;->OooO0Oo(Llyiahf/vczjk/ey6;J)Z

    move-result v5

    if-eqz v5, :cond_3

    goto/16 :goto_8

    :cond_3
    new-instance v5, Llyiahf/vczjk/gl7;

    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    iput-wide v0, v5, Llyiahf/vczjk/gl7;->element:J

    move-object v0, v5

    :goto_1
    iput-object v2, v3, Llyiahf/vczjk/oe2;->L$0:Ljava/lang/Object;

    iput-object v0, v3, Llyiahf/vczjk/oe2;->L$1:Ljava/lang/Object;

    iput v6, v3, Llyiahf/vczjk/oe2;->label:I

    sget-object v1, Llyiahf/vczjk/fy6;->OooOOO:Llyiahf/vczjk/fy6;

    invoke-virtual {v2, v1, v3}, Llyiahf/vczjk/kb9;->OooO00o(Llyiahf/vczjk/fy6;Llyiahf/vczjk/p70;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v4, :cond_4

    return-object v4

    :cond_4
    move-object/from16 v16, v2

    move-object v2, v1

    move-object/from16 v1, v16

    :goto_2
    check-cast v2, Llyiahf/vczjk/ey6;

    iget-object v5, v2, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    invoke-interface {v5}, Ljava/util/Collection;->size()I

    move-result v8

    const/4 v9, 0x0

    move v10, v9

    :goto_3
    if-ge v10, v8, :cond_6

    invoke-interface {v5, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v11

    move-object v12, v11

    check-cast v12, Llyiahf/vczjk/ky6;

    iget-wide v12, v12, Llyiahf/vczjk/ky6;->OooO00o:J

    iget-wide v14, v0, Llyiahf/vczjk/gl7;->element:J

    invoke-static {v12, v13, v14, v15}, Llyiahf/vczjk/tn6;->OooO0oo(JJ)Z

    move-result v12

    if-eqz v12, :cond_5

    goto :goto_4

    :cond_5
    add-int/lit8 v10, v10, 0x1

    goto :goto_3

    :cond_6
    move-object v11, v7

    :goto_4
    check-cast v11, Llyiahf/vczjk/ky6;

    if-nez v11, :cond_7

    move-object v11, v7

    goto :goto_7

    :cond_7
    invoke-static {v11}, Llyiahf/vczjk/vl6;->OooOO0(Llyiahf/vczjk/ky6;)Z

    move-result v5

    if-eqz v5, :cond_b

    iget-object v2, v2, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    invoke-interface {v2}, Ljava/util/Collection;->size()I

    move-result v5

    :goto_5
    if-ge v9, v5, :cond_9

    invoke-interface {v2, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v8

    move-object v10, v8

    check-cast v10, Llyiahf/vczjk/ky6;

    iget-boolean v10, v10, Llyiahf/vczjk/ky6;->OooO0Oo:Z

    if-eqz v10, :cond_8

    goto :goto_6

    :cond_8
    add-int/lit8 v9, v9, 0x1

    goto :goto_5

    :cond_9
    move-object v8, v7

    :goto_6
    check-cast v8, Llyiahf/vczjk/ky6;

    if-nez v8, :cond_a

    goto :goto_7

    :cond_a
    iget-wide v8, v8, Llyiahf/vczjk/ky6;->OooO00o:J

    iput-wide v8, v0, Llyiahf/vczjk/gl7;->element:J

    goto :goto_9

    :cond_b
    invoke-static {v11, v6}, Llyiahf/vczjk/vl6;->OooOoo0(Llyiahf/vczjk/ky6;Z)J

    move-result-wide v8

    const-wide/16 v12, 0x0

    invoke-static {v8, v9, v12, v13}, Llyiahf/vczjk/p86;->OooO0O0(JJ)Z

    move-result v2

    if-nez v2, :cond_d

    :goto_7
    if-eqz v11, :cond_c

    invoke-virtual {v11}, Llyiahf/vczjk/ky6;->OooO0O0()Z

    move-result v0

    if-nez v0, :cond_c

    return-object v11

    :cond_c
    :goto_8
    return-object v7

    :cond_d
    :goto_9
    move-object v2, v1

    goto :goto_1
.end method

.method public static final OooO0O0(Llyiahf/vczjk/kb9;JLlyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 9

    instance-of v0, p3, Llyiahf/vczjk/pe2;

    if-eqz v0, :cond_0

    move-object v0, p3

    check-cast v0, Llyiahf/vczjk/pe2;

    iget v1, v0, Llyiahf/vczjk/pe2;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/pe2;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/pe2;

    invoke-direct {v0, p3}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p3, v0, Llyiahf/vczjk/pe2;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/pe2;->label:I

    const/4 v3, 0x1

    const/4 v4, 0x0

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p0, v0, Llyiahf/vczjk/pe2;->L$2:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/dl7;

    iget-object p1, v0, Llyiahf/vczjk/pe2;->L$1:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/hl7;

    iget-object p2, v0, Llyiahf/vczjk/pe2;->L$0:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/ky6;

    :try_start_0
    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V
    :try_end_0
    .catch Llyiahf/vczjk/gy6; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_3

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    invoke-static {p3}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p3, p0, Llyiahf/vczjk/kb9;->OooOOo:Llyiahf/vczjk/nb9;

    iget-object p3, p3, Llyiahf/vczjk/nb9;->OooOooo:Llyiahf/vczjk/ey6;

    invoke-static {p3, p1, p2}, Llyiahf/vczjk/ve2;->OooO0Oo(Llyiahf/vczjk/ey6;J)Z

    move-result p3

    if-eqz p3, :cond_3

    goto :goto_4

    :cond_3
    iget-object p3, p0, Llyiahf/vczjk/kb9;->OooOOo:Llyiahf/vczjk/nb9;

    iget-object p3, p3, Llyiahf/vczjk/nb9;->OooOooo:Llyiahf/vczjk/ey6;

    iget-object p3, p3, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    invoke-interface {p3}, Ljava/util/Collection;->size()I

    move-result v2

    const/4 v5, 0x0

    :goto_1
    if-ge v5, v2, :cond_5

    invoke-interface {p3, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v6

    move-object v7, v6

    check-cast v7, Llyiahf/vczjk/ky6;

    iget-wide v7, v7, Llyiahf/vczjk/ky6;->OooO00o:J

    invoke-static {v7, v8, p1, p2}, Llyiahf/vczjk/tn6;->OooO0oo(JJ)Z

    move-result v7

    if-eqz v7, :cond_4

    goto :goto_2

    :cond_4
    add-int/lit8 v5, v5, 0x1

    goto :goto_1

    :cond_5
    move-object v6, v4

    :goto_2
    move-object p2, v6

    check-cast p2, Llyiahf/vczjk/ky6;

    if-nez p2, :cond_6

    goto :goto_4

    :cond_6
    new-instance p1, Llyiahf/vczjk/hl7;

    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    new-instance p3, Llyiahf/vczjk/hl7;

    invoke-direct {p3}, Ljava/lang/Object;-><init>()V

    iput-object p2, p3, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    invoke-virtual {p0}, Llyiahf/vczjk/kb9;->OooO0Oo()Llyiahf/vczjk/gga;

    move-result-object v2

    invoke-interface {v2}, Llyiahf/vczjk/gga;->OooO0O0()J

    move-result-wide v5

    :try_start_1
    new-instance v2, Llyiahf/vczjk/dl7;

    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    new-instance v7, Llyiahf/vczjk/qe2;

    invoke-direct {v7, v2, p3, p1, v4}, Llyiahf/vczjk/qe2;-><init>(Llyiahf/vczjk/dl7;Llyiahf/vczjk/hl7;Llyiahf/vczjk/hl7;Llyiahf/vczjk/yo1;)V

    iput-object p2, v0, Llyiahf/vczjk/pe2;->L$0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/pe2;->L$1:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/pe2;->L$2:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/pe2;->label:I

    invoke-virtual {p0, v5, v6, v7, v0}, Llyiahf/vczjk/kb9;->OooO0o(JLlyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p0

    if-ne p0, v1, :cond_7

    return-object v1

    :cond_7
    move-object p0, v2

    :goto_3
    iget-boolean p0, p0, Llyiahf/vczjk/dl7;->element:Z

    if-eqz p0, :cond_9

    iget-object p0, p1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/ky6;
    :try_end_1
    .catch Llyiahf/vczjk/gy6; {:try_start_1 .. :try_end_1} :catch_0

    if-nez p0, :cond_8

    return-object p2

    :cond_8
    return-object p0

    :cond_9
    :goto_4
    return-object v4

    :catch_0
    iget-object p0, p1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/ky6;

    if-nez p0, :cond_a

    goto :goto_5

    :cond_a
    move-object p2, p0

    :goto_5
    return-object p2
.end method

.method public static final OooO0OO(Llyiahf/vczjk/kb9;JLlyiahf/vczjk/oe3;Llyiahf/vczjk/p70;)Ljava/lang/Object;
    .locals 4

    instance-of v0, p4, Llyiahf/vczjk/ue2;

    if-eqz v0, :cond_0

    move-object v0, p4

    check-cast v0, Llyiahf/vczjk/ue2;

    iget v1, v0, Llyiahf/vczjk/ue2;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/ue2;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/ue2;

    invoke-direct {v0, p4}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p4, v0, Llyiahf/vczjk/ue2;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/ue2;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p0, v0, Llyiahf/vczjk/ue2;->L$1:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/oe3;

    iget-object p1, v0, Llyiahf/vczjk/ue2;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/kb9;

    invoke-static {p4}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object p3, p0

    move-object p0, p1

    goto :goto_2

    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_2
    invoke-static {p4}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    :goto_1
    iput-object p0, v0, Llyiahf/vczjk/ue2;->L$0:Ljava/lang/Object;

    iput-object p3, v0, Llyiahf/vczjk/ue2;->L$1:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/ue2;->label:I

    invoke-static {p0, p1, p2, v0}, Llyiahf/vczjk/ve2;->OooO00o(Llyiahf/vczjk/kb9;JLlyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p4

    if-ne p4, v1, :cond_3

    return-object v1

    :cond_3
    :goto_2
    check-cast p4, Llyiahf/vczjk/ky6;

    if-nez p4, :cond_4

    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    return-object p0

    :cond_4
    invoke-static {p4}, Llyiahf/vczjk/vl6;->OooOO0(Llyiahf/vczjk/ky6;)Z

    move-result p1

    if-eqz p1, :cond_5

    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p0

    :cond_5
    invoke-interface {p3, p4}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    iget-wide p1, p4, Llyiahf/vczjk/ky6;->OooO00o:J

    goto :goto_1
.end method

.method public static final OooO0Oo(Llyiahf/vczjk/ey6;J)Z
    .locals 6

    iget-object p0, p0, Llyiahf/vczjk/ey6;->OooO00o:Ljava/lang/Object;

    invoke-interface {p0}, Ljava/util/Collection;->size()I

    move-result v0

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    if-ge v2, v0, :cond_1

    invoke-interface {p0, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    move-object v4, v3

    check-cast v4, Llyiahf/vczjk/ky6;

    iget-wide v4, v4, Llyiahf/vczjk/ky6;->OooO00o:J

    invoke-static {v4, v5, p1, p2}, Llyiahf/vczjk/tn6;->OooO0oo(JJ)Z

    move-result v4

    if-eqz v4, :cond_0

    goto :goto_1

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    const/4 v3, 0x0

    :goto_1
    check-cast v3, Llyiahf/vczjk/ky6;

    const/4 p0, 0x1

    if-eqz v3, :cond_2

    iget-boolean p1, v3, Llyiahf/vczjk/ky6;->OooO0Oo:Z

    if-ne p1, p0, :cond_2

    move v1, p0

    :cond_2
    xor-int/2addr p0, v1

    return p0
.end method

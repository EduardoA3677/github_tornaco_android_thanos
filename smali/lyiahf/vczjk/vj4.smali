.class public final Llyiahf/vczjk/vj4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/xj2;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/uj4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/uj4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/vj4;->OooO00o:Llyiahf/vczjk/uj4;

    return-void
.end method


# virtual methods
.method public final bridge synthetic OooO00o(Llyiahf/vczjk/m1a;)Llyiahf/vczjk/aea;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/vj4;->OooO0oO(Llyiahf/vczjk/m1a;)Llyiahf/vczjk/eea;

    move-result-object p1

    return-object p1
.end method

.method public final bridge synthetic OooO00o(Llyiahf/vczjk/m1a;)Llyiahf/vczjk/yda;
    .locals 0

    invoke-virtual {p0, p1}, Llyiahf/vczjk/vj4;->OooO0oO(Llyiahf/vczjk/m1a;)Llyiahf/vczjk/eea;

    move-result-object p1

    return-object p1
.end method

.method public final bridge synthetic OooO0o()Llyiahf/vczjk/bea;
    .locals 1

    sget-object v0, Llyiahf/vczjk/gda;->OooO00o:Llyiahf/vczjk/n1a;

    invoke-virtual {p0, v0}, Llyiahf/vczjk/vj4;->OooO0oO(Llyiahf/vczjk/m1a;)Llyiahf/vczjk/eea;

    move-result-object v0

    return-object v0
.end method

.method public final OooO0oO(Llyiahf/vczjk/m1a;)Llyiahf/vczjk/eea;
    .locals 20

    new-instance v0, Llyiahf/vczjk/nr5;

    move-object/from16 v1, p0

    iget-object v2, v1, Llyiahf/vczjk/vj4;->OooO00o:Llyiahf/vczjk/uj4;

    iget-object v3, v2, Llyiahf/vczjk/uj4;->OooO0O0:Llyiahf/vczjk/or5;

    iget v4, v3, Llyiahf/vczjk/s14;->OooO0o0:I

    add-int/lit8 v4, v4, 0x2

    invoke-direct {v0, v4}, Llyiahf/vczjk/nr5;-><init>(I)V

    new-instance v4, Llyiahf/vczjk/or5;

    iget v5, v3, Llyiahf/vczjk/s14;->OooO0o0:I

    invoke-direct {v4, v5}, Llyiahf/vczjk/or5;-><init>(I)V

    iget-object v5, v3, Llyiahf/vczjk/s14;->OooO0O0:[I

    iget-object v6, v3, Llyiahf/vczjk/s14;->OooO0OO:[Ljava/lang/Object;

    iget-object v7, v3, Llyiahf/vczjk/s14;->OooO00o:[J

    array-length v8, v7

    add-int/lit8 v8, v8, -0x2

    if-ltz v8, :cond_2

    const/4 v10, 0x0

    :goto_0
    aget-wide v11, v7, v10

    not-long v13, v11

    const/4 v15, 0x7

    shl-long/2addr v13, v15

    and-long/2addr v13, v11

    const-wide v15, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    and-long/2addr v13, v15

    cmp-long v13, v13, v15

    if-eqz v13, :cond_3

    sub-int v13, v10, v8

    not-int v13, v13

    ushr-int/lit8 v13, v13, 0x1f

    const/16 v14, 0x8

    rsub-int/lit8 v13, v13, 0x8

    const/4 v15, 0x0

    :goto_1
    if-ge v15, v13, :cond_1

    const-wide/16 v16, 0xff

    and-long v16, v11, v16

    const-wide/16 v18, 0x80

    cmp-long v16, v16, v18

    if-gez v16, :cond_0

    shl-int/lit8 v16, v10, 0x3

    add-int v16, v16, v15

    aget v9, v5, v16

    aget-object v16, v6, v16

    move/from16 v18, v14

    move-object/from16 v14, v16

    check-cast v14, Llyiahf/vczjk/tj4;

    invoke-virtual {v0, v9}, Llyiahf/vczjk/nr5;->OooO00o(I)V

    new-instance v1, Llyiahf/vczjk/dea;

    move-object/from16 v16, v5

    move-object/from16 v5, p1

    check-cast v5, Llyiahf/vczjk/n1a;

    iget-object v5, v5, Llyiahf/vczjk/n1a;->OooO00o:Llyiahf/vczjk/oe3;

    move-object/from16 v19, v6

    iget-object v6, v14, Llyiahf/vczjk/tj4;->OooO00o:Ljava/lang/Object;

    invoke-interface {v5, v6}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Llyiahf/vczjk/dm;

    iget-object v6, v14, Llyiahf/vczjk/tj4;->OooO0O0:Llyiahf/vczjk/ik2;

    invoke-direct {v1, v5, v6}, Llyiahf/vczjk/dea;-><init>(Llyiahf/vczjk/dm;Llyiahf/vczjk/ik2;)V

    invoke-virtual {v4, v9, v1}, Llyiahf/vczjk/or5;->OooO0oo(ILjava/lang/Object;)V

    goto :goto_2

    :cond_0
    move-object/from16 v16, v5

    move-object/from16 v19, v6

    move/from16 v18, v14

    :goto_2
    shr-long v11, v11, v18

    add-int/lit8 v15, v15, 0x1

    move-object/from16 v1, p0

    move-object/from16 v5, v16

    move/from16 v14, v18

    move-object/from16 v6, v19

    goto :goto_1

    :cond_1
    move-object/from16 v16, v5

    move-object/from16 v19, v6

    move v1, v14

    if-ne v13, v1, :cond_2

    goto :goto_3

    :cond_2
    const/4 v1, 0x0

    goto :goto_4

    :cond_3
    move-object/from16 v16, v5

    move-object/from16 v19, v6

    :goto_3
    if-eq v10, v8, :cond_2

    add-int/lit8 v10, v10, 0x1

    move-object/from16 v1, p0

    move-object/from16 v5, v16

    move-object/from16 v6, v19

    goto :goto_0

    :goto_4
    invoke-virtual {v3, v1}, Llyiahf/vczjk/s14;->OooO00o(I)Z

    move-result v5

    if-nez v5, :cond_6

    iget v5, v0, Llyiahf/vczjk/nr5;->OooO0O0:I

    if-ltz v5, :cond_5

    const/4 v6, 0x1

    add-int/2addr v5, v6

    invoke-virtual {v0, v5}, Llyiahf/vczjk/nr5;->OooO0O0(I)V

    iget-object v5, v0, Llyiahf/vczjk/nr5;->OooO00o:[I

    iget v7, v0, Llyiahf/vczjk/nr5;->OooO0O0:I

    if-eqz v7, :cond_4

    invoke-static {v6, v1, v7, v5, v5}, Llyiahf/vczjk/sy;->ooOO(III[I[I)V

    :cond_4
    aput v1, v5, v1

    iget v1, v0, Llyiahf/vczjk/nr5;->OooO0O0:I

    add-int/2addr v1, v6

    iput v1, v0, Llyiahf/vczjk/nr5;->OooO0O0:I

    goto :goto_5

    :cond_5
    const-string v0, "Index must be between 0 and size"

    invoke-static {v0}, Llyiahf/vczjk/vt6;->Oooo0o0(Ljava/lang/String;)V

    const/4 v0, 0x0

    throw v0

    :cond_6
    :goto_5
    iget v1, v2, Llyiahf/vczjk/uj4;->OooO00o:I

    invoke-virtual {v3, v1}, Llyiahf/vczjk/s14;->OooO00o(I)Z

    move-result v1

    if-nez v1, :cond_7

    iget v1, v2, Llyiahf/vczjk/uj4;->OooO00o:I

    invoke-virtual {v0, v1}, Llyiahf/vczjk/nr5;->OooO00o(I)V

    :cond_7
    iget v1, v0, Llyiahf/vczjk/nr5;->OooO0O0:I

    if-nez v1, :cond_8

    goto :goto_6

    :cond_8
    iget-object v3, v0, Llyiahf/vczjk/nr5;->OooO00o:[I

    const-string v5, "<this>"

    invoke-static {v3, v5}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v5, 0x0

    invoke-static {v3, v5, v1}, Ljava/util/Arrays;->sort([III)V

    :goto_6
    new-instance v1, Llyiahf/vczjk/eea;

    iget v2, v2, Llyiahf/vczjk/uj4;->OooO00o:I

    sget-object v3, Llyiahf/vczjk/jk2;->OooO0Oo:Llyiahf/vczjk/oOO0O00O;

    invoke-direct {v1, v0, v4, v2, v3}, Llyiahf/vczjk/eea;-><init>(Llyiahf/vczjk/nr5;Llyiahf/vczjk/or5;ILlyiahf/vczjk/oOO0O00O;)V

    return-object v1
.end method

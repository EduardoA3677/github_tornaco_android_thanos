.class public final Llyiahf/vczjk/ow8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $appliedChanges:Llyiahf/vczjk/rs0;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/rs0;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/jj0;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ow8;->$appliedChanges:Llyiahf/vczjk/rs0;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    move-object/from16 v0, p1

    check-cast v0, Ljava/util/Set;

    move-object/from16 v1, p2

    check-cast v1, Llyiahf/vczjk/nv8;

    instance-of v1, v0, Llyiahf/vczjk/d88;

    const/4 v2, 0x4

    if-eqz v1, :cond_5

    move-object v1, v0

    check-cast v1, Llyiahf/vczjk/d88;

    iget-object v1, v1, Llyiahf/vczjk/d88;->OooOOO0:Llyiahf/vczjk/a88;

    iget-object v3, v1, Llyiahf/vczjk/a88;->OooO0O0:[Ljava/lang/Object;

    iget-object v1, v1, Llyiahf/vczjk/a88;->OooO00o:[J

    array-length v4, v1

    add-int/lit8 v4, v4, -0x2

    if-ltz v4, :cond_4

    const/4 v5, 0x0

    move v6, v5

    :goto_0
    aget-wide v7, v1, v6

    not-long v9, v7

    const/4 v11, 0x7

    shl-long/2addr v9, v11

    and-long/2addr v9, v7

    const-wide v11, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    and-long/2addr v9, v11

    cmp-long v9, v9, v11

    if-eqz v9, :cond_3

    sub-int v9, v6, v4

    not-int v9, v9

    ushr-int/lit8 v9, v9, 0x1f

    const/16 v10, 0x8

    rsub-int/lit8 v9, v9, 0x8

    move v11, v5

    :goto_1
    if-ge v11, v9, :cond_2

    const-wide/16 v12, 0xff

    and-long/2addr v12, v7

    const-wide/16 v14, 0x80

    cmp-long v12, v12, v14

    if-gez v12, :cond_1

    shl-int/lit8 v12, v6, 0x3

    add-int/2addr v12, v11

    aget-object v12, v3, v12

    instance-of v13, v12, Llyiahf/vczjk/c39;

    if-eqz v13, :cond_0

    check-cast v12, Llyiahf/vczjk/c39;

    invoke-virtual {v12, v2}, Llyiahf/vczjk/c39;->OooOOOO(I)Z

    move-result v12

    if-eqz v12, :cond_1

    :cond_0
    :goto_2
    move-object/from16 v1, p0

    goto :goto_4

    :cond_1
    shr-long/2addr v7, v10

    add-int/lit8 v11, v11, 0x1

    goto :goto_1

    :cond_2
    if-ne v9, v10, :cond_4

    :cond_3
    if-eq v6, v4, :cond_4

    add-int/lit8 v6, v6, 0x1

    goto :goto_0

    :cond_4
    :goto_3
    move-object/from16 v1, p0

    goto :goto_5

    :cond_5
    move-object v1, v0

    check-cast v1, Ljava/lang/Iterable;

    instance-of v3, v1, Ljava/util/Collection;

    if-eqz v3, :cond_6

    move-object v3, v1

    check-cast v3, Ljava/util/Collection;

    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    move-result v3

    if-eqz v3, :cond_6

    goto :goto_3

    :cond_6
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :cond_7
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    instance-of v4, v3, Llyiahf/vczjk/c39;

    if-eqz v4, :cond_0

    check-cast v3, Llyiahf/vczjk/c39;

    invoke-virtual {v3, v2}, Llyiahf/vczjk/c39;->OooOOOO(I)Z

    move-result v3

    if-eqz v3, :cond_7

    goto :goto_2

    :goto_4
    iget-object v2, v1, Llyiahf/vczjk/ow8;->$appliedChanges:Llyiahf/vczjk/rs0;

    invoke-interface {v2, v0}, Llyiahf/vczjk/if8;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    :goto_5
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method

.class public final Llyiahf/vczjk/gj7;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $composition:Llyiahf/vczjk/cp1;

.field final synthetic $modifiedValues:Llyiahf/vczjk/ks5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/ks5;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/cp1;Llyiahf/vczjk/ks5;)V
    .locals 0

    iput-object p2, p0, Llyiahf/vczjk/gj7;->$modifiedValues:Llyiahf/vczjk/ks5;

    iput-object p1, p0, Llyiahf/vczjk/gj7;->$composition:Llyiahf/vczjk/cp1;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 15

    iget-object v0, p0, Llyiahf/vczjk/gj7;->$modifiedValues:Llyiahf/vczjk/ks5;

    iget-object v1, p0, Llyiahf/vczjk/gj7;->$composition:Llyiahf/vczjk/cp1;

    iget-object v2, v0, Llyiahf/vczjk/a88;->OooO0O0:[Ljava/lang/Object;

    iget-object v0, v0, Llyiahf/vczjk/a88;->OooO00o:[J

    array-length v3, v0

    add-int/lit8 v3, v3, -0x2

    if-ltz v3, :cond_3

    const/4 v4, 0x0

    move v5, v4

    :goto_0
    aget-wide v6, v0, v5

    not-long v8, v6

    const/4 v10, 0x7

    shl-long/2addr v8, v10

    and-long/2addr v8, v6

    const-wide v10, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    and-long/2addr v8, v10

    cmp-long v8, v8, v10

    if-eqz v8, :cond_2

    sub-int v8, v5, v3

    not-int v8, v8

    ushr-int/lit8 v8, v8, 0x1f

    const/16 v9, 0x8

    rsub-int/lit8 v8, v8, 0x8

    move v10, v4

    :goto_1
    if-ge v10, v8, :cond_1

    const-wide/16 v11, 0xff

    and-long/2addr v11, v6

    const-wide/16 v13, 0x80

    cmp-long v11, v11, v13

    if-gez v11, :cond_0

    shl-int/lit8 v11, v5, 0x3

    add-int/2addr v11, v10

    aget-object v11, v2, v11

    move-object v12, v1

    check-cast v12, Llyiahf/vczjk/sg1;

    invoke-virtual {v12, v11}, Llyiahf/vczjk/sg1;->OooOoO0(Ljava/lang/Object;)V

    :cond_0
    shr-long/2addr v6, v9

    add-int/lit8 v10, v10, 0x1

    goto :goto_1

    :cond_1
    if-ne v8, v9, :cond_3

    :cond_2
    if-eq v5, v3, :cond_3

    add-int/lit8 v5, v5, 0x1

    goto :goto_0

    :cond_3
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method

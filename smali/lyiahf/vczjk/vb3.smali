.class public final Llyiahf/vczjk/vb3;
.super Llyiahf/vczjk/u34;
.source "SourceFile"


# static fields
.field public static final OooOo0:Llyiahf/vczjk/vb3;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/vb3;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/vb3;->OooOo0:Llyiahf/vczjk/vb3;

    return-void
.end method


# virtual methods
.method public final OooOO0o()I
    .locals 1

    const/4 v0, 0x3

    return v0
.end method

.method public final OooOooo(Llyiahf/vczjk/v13;)Ljava/lang/String;
    .locals 0

    invoke-static {p1}, Llyiahf/vczjk/u34;->OooOO0(Llyiahf/vczjk/v13;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public final Oooo0(Llyiahf/vczjk/aw1;)Z
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/gg9;

    if-eqz v0, :cond_0

    iget-object p1, p1, Llyiahf/vczjk/aw1;->OooO0OO:Llyiahf/vczjk/tn7;

    iget-object p1, p1, Llyiahf/vczjk/x13;->OooOOO:[Ljava/lang/Object;

    array-length p1, p1

    if-nez p1, :cond_0

    const/4 p1, 0x1

    return p1

    :cond_0
    const/4 p1, 0x0

    return p1
.end method

.method public final Oooo000(Llyiahf/vczjk/v13;)Ljava/lang/String;
    .locals 0

    invoke-static {p1}, Llyiahf/vczjk/u34;->OooO0oO(Llyiahf/vczjk/v13;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

.method public final o00Ooo(Llyiahf/vczjk/ol0;Llyiahf/vczjk/v13;)V
    .locals 2

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/gg9;

    invoke-virtual {v0}, Llyiahf/vczjk/gg9;->OooOOO0()I

    move-result v0

    const/4 v1, 0x0

    invoke-static {p2, v1}, Llyiahf/vczjk/u34;->Oooo(Llyiahf/vczjk/aw1;I)S

    move-result p2

    int-to-short v1, v0

    shr-int/lit8 v0, v0, 0x10

    int-to-short v0, v0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ol0;->OooOO0O(I)V

    invoke-virtual {p1, v1}, Llyiahf/vczjk/ol0;->OooOO0O(I)V

    invoke-virtual {p1, v0}, Llyiahf/vczjk/ol0;->OooOO0O(I)V

    return-void
.end method

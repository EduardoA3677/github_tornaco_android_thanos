.class public Llyiahf/vczjk/foa;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0O0:Llyiahf/vczjk/ioa;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ioa;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x22

    if-lt v0, v1, :cond_0

    new-instance v0, Llyiahf/vczjk/xna;

    invoke-direct {v0}, Llyiahf/vczjk/xna;-><init>()V

    goto :goto_0

    :cond_0
    const/16 v1, 0x1e

    if-lt v0, v1, :cond_1

    new-instance v0, Llyiahf/vczjk/wna;

    invoke-direct {v0}, Llyiahf/vczjk/wna;-><init>()V

    goto :goto_0

    :cond_1
    const/16 v1, 0x1d

    if-lt v0, v1, :cond_2

    new-instance v0, Llyiahf/vczjk/vna;

    invoke-direct {v0}, Llyiahf/vczjk/vna;-><init>()V

    goto :goto_0

    :cond_2
    new-instance v0, Llyiahf/vczjk/tna;

    invoke-direct {v0}, Llyiahf/vczjk/tna;-><init>()V

    :goto_0
    invoke-virtual {v0}, Llyiahf/vczjk/yna;->OooO0O0()Llyiahf/vczjk/ioa;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    invoke-virtual {v0}, Llyiahf/vczjk/foa;->OooO00o()Llyiahf/vczjk/ioa;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    invoke-virtual {v0}, Llyiahf/vczjk/foa;->OooO0O0()Llyiahf/vczjk/ioa;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/ioa;->OooO00o:Llyiahf/vczjk/foa;

    invoke-virtual {v0}, Llyiahf/vczjk/foa;->OooO0OO()Llyiahf/vczjk/ioa;

    move-result-object v0

    sput-object v0, Llyiahf/vczjk/foa;->OooO0O0:Llyiahf/vczjk/ioa;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/ioa;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/foa;->OooO00o:Llyiahf/vczjk/ioa;

    return-void
.end method


# virtual methods
.method public OooO()Llyiahf/vczjk/x04;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/foa;->OooOO0o()Llyiahf/vczjk/x04;

    move-result-object v0

    return-object v0
.end method

.method public OooO00o()Llyiahf/vczjk/ioa;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/foa;->OooO00o:Llyiahf/vczjk/ioa;

    return-object v0
.end method

.method public OooO0O0()Llyiahf/vczjk/ioa;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/foa;->OooO00o:Llyiahf/vczjk/ioa;

    return-object v0
.end method

.method public OooO0OO()Llyiahf/vczjk/ioa;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/foa;->OooO00o:Llyiahf/vczjk/ioa;

    return-object v0
.end method

.method public OooO0Oo(Landroid/view/View;)V
    .locals 0

    return-void
.end method

.method public OooO0o()Llyiahf/vczjk/lc2;
    .locals 1

    const/4 v0, 0x0

    return-object v0
.end method

.method public OooO0o0(Llyiahf/vczjk/ioa;)V
    .locals 0

    return-void
.end method

.method public OooO0oO(I)Llyiahf/vczjk/x04;
    .locals 0

    sget-object p1, Llyiahf/vczjk/x04;->OooO0o0:Llyiahf/vczjk/x04;

    return-object p1
.end method

.method public OooO0oo(I)Llyiahf/vczjk/x04;
    .locals 1

    and-int/lit8 p1, p1, 0x8

    if-nez p1, :cond_0

    sget-object p1, Llyiahf/vczjk/x04;->OooO0o0:Llyiahf/vczjk/x04;

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Unable to query the maximum insets for IME"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

.method public OooOO0()Llyiahf/vczjk/x04;
    .locals 1

    sget-object v0, Llyiahf/vczjk/x04;->OooO0o0:Llyiahf/vczjk/x04;

    return-object v0
.end method

.method public OooOO0O()Llyiahf/vczjk/x04;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/foa;->OooOO0o()Llyiahf/vczjk/x04;

    move-result-object v0

    return-object v0
.end method

.method public OooOO0o()Llyiahf/vczjk/x04;
    .locals 1

    sget-object v0, Llyiahf/vczjk/x04;->OooO0o0:Llyiahf/vczjk/x04;

    return-object v0
.end method

.method public OooOOO(IIII)Llyiahf/vczjk/ioa;
    .locals 0

    sget-object p1, Llyiahf/vczjk/foa;->OooO0O0:Llyiahf/vczjk/ioa;

    return-object p1
.end method

.method public OooOOO0()Llyiahf/vczjk/x04;
    .locals 1

    invoke-virtual {p0}, Llyiahf/vczjk/foa;->OooOO0o()Llyiahf/vczjk/x04;

    move-result-object v0

    return-object v0
.end method

.method public OooOOOO()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public OooOOOo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public OooOOo([Llyiahf/vczjk/x04;)V
    .locals 0

    return-void
.end method

.method public OooOOo0(I)Z
    .locals 0

    const/4 p1, 0x1

    return p1
.end method

.method public OooOOoo(Llyiahf/vczjk/x04;)V
    .locals 0

    return-void
.end method

.method public OooOo0(Llyiahf/vczjk/x04;)V
    .locals 0

    return-void
.end method

.method public OooOo00(Llyiahf/vczjk/ioa;)V
    .locals 0

    return-void
.end method

.method public OooOo0O(I)V
    .locals 0

    return-void
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    const/4 v0, 0x1

    if-ne p0, p1, :cond_0

    return v0

    :cond_0
    instance-of v1, p1, Llyiahf/vczjk/foa;

    const/4 v2, 0x0

    if-nez v1, :cond_1

    return v2

    :cond_1
    check-cast p1, Llyiahf/vczjk/foa;

    invoke-virtual {p0}, Llyiahf/vczjk/foa;->OooOOOo()Z

    move-result v1

    invoke-virtual {p1}, Llyiahf/vczjk/foa;->OooOOOo()Z

    move-result v3

    if-ne v1, v3, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/foa;->OooOOOO()Z

    move-result v1

    invoke-virtual {p1}, Llyiahf/vczjk/foa;->OooOOOO()Z

    move-result v3

    if-ne v1, v3, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/foa;->OooOO0o()Llyiahf/vczjk/x04;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/foa;->OooOO0o()Llyiahf/vczjk/x04;

    move-result-object v3

    invoke-static {v1, v3}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/foa;->OooOO0()Llyiahf/vczjk/x04;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/foa;->OooOO0()Llyiahf/vczjk/x04;

    move-result-object v3

    invoke-static {v1, v3}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-virtual {p0}, Llyiahf/vczjk/foa;->OooO0o()Llyiahf/vczjk/lc2;

    move-result-object v1

    invoke-virtual {p1}, Llyiahf/vczjk/foa;->OooO0o()Llyiahf/vczjk/lc2;

    move-result-object p1

    invoke-static {v1, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result p1

    if-eqz p1, :cond_2

    return v0

    :cond_2
    return v2
.end method

.method public hashCode()I
    .locals 5

    invoke-virtual {p0}, Llyiahf/vczjk/foa;->OooOOOo()Z

    move-result v0

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    invoke-virtual {p0}, Llyiahf/vczjk/foa;->OooOOOO()Z

    move-result v1

    invoke-static {v1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v1

    invoke-virtual {p0}, Llyiahf/vczjk/foa;->OooOO0o()Llyiahf/vczjk/x04;

    move-result-object v2

    invoke-virtual {p0}, Llyiahf/vczjk/foa;->OooOO0()Llyiahf/vczjk/x04;

    move-result-object v3

    invoke-virtual {p0}, Llyiahf/vczjk/foa;->OooO0o()Llyiahf/vczjk/lc2;

    move-result-object v4

    filled-new-array {v0, v1, v2, v3, v4}, [Ljava/lang/Object;

    move-result-object v0

    invoke-static {v0}, Ljava/util/Objects;->hash([Ljava/lang/Object;)I

    move-result v0

    return v0
.end method

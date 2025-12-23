.class public abstract Llyiahf/vczjk/v94;
.super Llyiahf/vczjk/yg3;
.source "SourceFile"


# static fields
.field public static final OooOo0o:[I


# instance fields
.field public final OooOOo:Llyiahf/vczjk/t01;

.field public OooOOoo:[I

.field public OooOo0:Llyiahf/vczjk/fg8;

.field public OooOo00:I

.field public OooOo0O:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    sget-object v0, Llyiahf/vczjk/vt0;->OooO0oo:[I

    sput-object v0, Llyiahf/vczjk/v94;->OooOo0o:[I

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/t01;I)V
    .locals 4

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p2, p0, Llyiahf/vczjk/yg3;->OooOOO:I

    sget-object v0, Llyiahf/vczjk/t94;->OooOo0:Llyiahf/vczjk/t94;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/t94;->OooO0O0(I)Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    new-instance v0, Llyiahf/vczjk/ld9;

    invoke-direct {v0, p0}, Llyiahf/vczjk/ld9;-><init>(Ljava/io/Closeable;)V

    goto :goto_0

    :cond_0
    move-object v0, v1

    :goto_0
    new-instance v2, Llyiahf/vczjk/yc4;

    const/4 v3, 0x0

    invoke-direct {v2, v3, v1, v0}, Llyiahf/vczjk/yc4;-><init>(ILlyiahf/vczjk/yc4;Llyiahf/vczjk/ld9;)V

    iput-object v2, p0, Llyiahf/vczjk/yg3;->OooOOOo:Llyiahf/vczjk/yc4;

    sget-object v0, Llyiahf/vczjk/t94;->OooOOoo:Llyiahf/vczjk/t94;

    invoke-virtual {v0, p2}, Llyiahf/vczjk/t94;->OooO0O0(I)Z

    move-result v0

    iput-boolean v0, p0, Llyiahf/vczjk/yg3;->OooOOOO:Z

    sget-object v0, Llyiahf/vczjk/v94;->OooOo0o:[I

    iput-object v0, p0, Llyiahf/vczjk/v94;->OooOOoo:[I

    sget-object v0, Llyiahf/vczjk/j32;->OooOOO:Llyiahf/vczjk/ng8;

    iput-object v0, p0, Llyiahf/vczjk/v94;->OooOo0:Llyiahf/vczjk/fg8;

    iput-object p1, p0, Llyiahf/vczjk/v94;->OooOOo:Llyiahf/vczjk/t01;

    sget-object p1, Llyiahf/vczjk/t94;->OooOOo:Llyiahf/vczjk/t94;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/t94;->OooO0O0(I)Z

    move-result p1

    if-eqz p1, :cond_1

    const/16 p1, 0x7f

    iput p1, p0, Llyiahf/vczjk/v94;->OooOo00:I

    :cond_1
    sget-object p1, Llyiahf/vczjk/t94;->OooOOOo:Llyiahf/vczjk/t94;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/t94;->OooO0O0(I)Z

    move-result p1

    xor-int/lit8 p1, p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/v94;->OooOo0O:Z

    return-void
.end method


# virtual methods
.method public final OooOoO(Llyiahf/vczjk/t94;)Llyiahf/vczjk/u94;
    .locals 1

    invoke-super {p0, p1}, Llyiahf/vczjk/yg3;->OooOoO(Llyiahf/vczjk/t94;)Llyiahf/vczjk/u94;

    sget-object v0, Llyiahf/vczjk/t94;->OooOOOo:Llyiahf/vczjk/t94;

    if-ne p1, v0, :cond_0

    const/4 p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/v94;->OooOo0O:Z

    :cond_0
    return-object p0
.end method

.method public final OoooOoo(I)V
    .locals 0

    if-gez p1, :cond_0

    const/4 p1, 0x0

    :cond_0
    iput p1, p0, Llyiahf/vczjk/v94;->OooOo00:I

    return-void
.end method

.method public final o000O0O(Ljava/lang/String;)V
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/yg3;->OooOOOo:Llyiahf/vczjk/yc4;

    invoke-virtual {v0}, Llyiahf/vczjk/b23;->OooOO0O()Ljava/lang/String;

    move-result-object v0

    const-string v1, "Can not "

    const-string v2, ", expecting field name (context: "

    const-string v3, ")"

    invoke-static {v1, p1, v2, v0, v3}, Llyiahf/vczjk/ii5;->OooOO0(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/u94;->OooO0Oo(Ljava/lang/String;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final o000O0o(II)V
    .locals 0

    invoke-super {p0, p1, p2}, Llyiahf/vczjk/yg3;->o000O0o(II)V

    sget-object p2, Llyiahf/vczjk/t94;->OooOOOo:Llyiahf/vczjk/t94;

    invoke-virtual {p2, p1}, Llyiahf/vczjk/t94;->OooO0O0(I)Z

    move-result p1

    xor-int/lit8 p1, p1, 0x1

    iput-boolean p1, p0, Llyiahf/vczjk/v94;->OooOo0O:Z

    return-void
.end method

.method public final o000Oo0(ILjava/lang/String;)V
    .locals 2

    if-eqz p1, :cond_4

    const/4 v0, 0x1

    if-eq p1, v0, :cond_3

    const/4 v0, 0x2

    if-eq p1, v0, :cond_2

    const/4 v0, 0x3

    if-eq p1, v0, :cond_1

    const/4 v0, 0x5

    const/4 v1, 0x0

    if-eq p1, v0, :cond_0

    invoke-static {}, Llyiahf/vczjk/yea;->OooO00o()V

    throw v1

    :cond_0
    invoke-virtual {p0, p2}, Llyiahf/vczjk/v94;->o000O0O(Ljava/lang/String;)V

    throw v1

    :cond_1
    iget-object p1, p0, Llyiahf/vczjk/u94;->OooOOO0:Llyiahf/vczjk/u37;

    invoke-interface {p1, p0}, Llyiahf/vczjk/u37;->OooO0O0(Llyiahf/vczjk/v94;)V

    return-void

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/u94;->OooOOO0:Llyiahf/vczjk/u37;

    invoke-interface {p1, p0}, Llyiahf/vczjk/u37;->OooO(Llyiahf/vczjk/v94;)V

    return-void

    :cond_3
    iget-object p1, p0, Llyiahf/vczjk/u94;->OooOOO0:Llyiahf/vczjk/u37;

    invoke-interface {p1, p0}, Llyiahf/vczjk/u37;->OooO0OO(Llyiahf/vczjk/v94;)V

    return-void

    :cond_4
    iget-object p1, p0, Llyiahf/vczjk/yg3;->OooOOOo:Llyiahf/vczjk/yc4;

    invoke-virtual {p1}, Llyiahf/vczjk/b23;->OooO0oO()Z

    move-result p1

    if-eqz p1, :cond_5

    iget-object p1, p0, Llyiahf/vczjk/u94;->OooOOO0:Llyiahf/vczjk/u37;

    invoke-interface {p1, p0}, Llyiahf/vczjk/u37;->OooOO0(Llyiahf/vczjk/v94;)V

    return-void

    :cond_5
    iget-object p1, p0, Llyiahf/vczjk/yg3;->OooOOOo:Llyiahf/vczjk/yc4;

    invoke-virtual {p1}, Llyiahf/vczjk/b23;->OooO0oo()Z

    move-result p1

    if-eqz p1, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/u94;->OooOOO0:Llyiahf/vczjk/u37;

    invoke-interface {p1, p0}, Llyiahf/vczjk/u37;->OooO00o(Llyiahf/vczjk/u94;)V

    :cond_6
    return-void
.end method

.method public final o0OoOo0(Llyiahf/vczjk/fg8;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/v94;->OooOo0:Llyiahf/vczjk/fg8;

    return-void
.end method

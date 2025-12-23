.class public final enum Llyiahf/vczjk/ju9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "ScriptDataLessthanSign"

    const/16 v1, 0x10

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 2

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO0Oo()C

    move-result v0

    const/16 v1, 0x21

    if-eq v0, v1, :cond_1

    const/16 v1, 0x2f

    if-eq v0, v1, :cond_0

    const-string v0, "<"

    invoke-virtual {p1, v0}, Llyiahf/vczjk/bu9;->OooO0oO(Ljava/lang/String;)V

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooOOo0()V

    sget-object p2, Llyiahf/vczjk/rw9;->OooOOo:Llyiahf/vczjk/nw9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/bu9;->OooO0o0()V

    sget-object p2, Llyiahf/vczjk/rw9;->OooOoo:Llyiahf/vczjk/ku9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void

    :cond_1
    const-string p2, "<!"

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO0oO(Ljava/lang/String;)V

    sget-object p2, Llyiahf/vczjk/rw9;->OooOooo:Llyiahf/vczjk/nu9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void
.end method

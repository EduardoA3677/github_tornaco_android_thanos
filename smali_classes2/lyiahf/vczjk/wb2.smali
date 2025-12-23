.class public final Llyiahf/vczjk/wb2;
.super Llyiahf/vczjk/g5a;
.source "SourceFile"


# instance fields
.field public final OooO0O0:Llyiahf/vczjk/g5a;

.field public final OooO0OO:Llyiahf/vczjk/g5a;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/g5a;Llyiahf/vczjk/g5a;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/wb2;->OooO0O0:Llyiahf/vczjk/g5a;

    iput-object p2, p0, Llyiahf/vczjk/wb2;->OooO0OO:Llyiahf/vczjk/g5a;

    return-void
.end method


# virtual methods
.method public final OooO00o()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wb2;->OooO0O0:Llyiahf/vczjk/g5a;

    invoke-virtual {v0}, Llyiahf/vczjk/g5a;->OooO00o()Z

    move-result v0

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/wb2;->OooO0OO:Llyiahf/vczjk/g5a;

    invoke-virtual {v0}, Llyiahf/vczjk/g5a;->OooO00o()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    return v0

    :cond_1
    :goto_0
    const/4 v0, 0x1

    return v0
.end method

.method public final OooO0O0()Z
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wb2;->OooO0O0:Llyiahf/vczjk/g5a;

    invoke-virtual {v0}, Llyiahf/vczjk/g5a;->OooO0O0()Z

    move-result v0

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/wb2;->OooO0OO:Llyiahf/vczjk/g5a;

    invoke-virtual {v0}, Llyiahf/vczjk/g5a;->OooO0O0()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    return v0

    :cond_1
    :goto_0
    const/4 v0, 0x1

    return v0
.end method

.method public final OooO0OO(Llyiahf/vczjk/ko;)Llyiahf/vczjk/ko;
    .locals 1

    const-string v0, "annotations"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/wb2;->OooO0O0:Llyiahf/vczjk/g5a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/g5a;->OooO0OO(Llyiahf/vczjk/ko;)Llyiahf/vczjk/ko;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/wb2;->OooO0OO:Llyiahf/vczjk/g5a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/g5a;->OooO0OO(Llyiahf/vczjk/ko;)Llyiahf/vczjk/ko;

    move-result-object p1

    return-object p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/z4a;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/wb2;->OooO0O0:Llyiahf/vczjk/g5a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/g5a;->OooO0Oo(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/z4a;

    move-result-object v0

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/wb2;->OooO0OO:Llyiahf/vczjk/g5a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/g5a;->OooO0Oo(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/z4a;

    move-result-object p1

    return-object p1

    :cond_0
    return-object v0
.end method

.method public final OooO0o(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;
    .locals 1

    const-string v0, "topLevelType"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "position"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p0, Llyiahf/vczjk/wb2;->OooO0O0:Llyiahf/vczjk/g5a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/g5a;->OooO0o(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object p1

    iget-object v0, p0, Llyiahf/vczjk/wb2;->OooO0OO:Llyiahf/vczjk/g5a;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/g5a;->OooO0o(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;

    move-result-object p1

    return-object p1
.end method

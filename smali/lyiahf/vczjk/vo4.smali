.class public final Llyiahf/vczjk/vo4;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public OooO:I

.field public final OooO00o:Llyiahf/vczjk/ro4;

.field public OooO0O0:Z

.field public OooO0OO:Z

.field public OooO0Oo:Llyiahf/vczjk/lo4;

.field public OooO0o:Z

.field public OooO0o0:Z

.field public OooO0oO:Z

.field public OooO0oo:I

.field public OooOO0:Z

.field public OooOO0O:Z

.field public OooOO0o:I

.field public OooOOO:Z

.field public OooOOO0:Z

.field public OooOOOO:I

.field public final OooOOOo:Llyiahf/vczjk/kf5;

.field public OooOOo0:Llyiahf/vczjk/w65;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ro4;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    sget-object p1, Llyiahf/vczjk/lo4;->OooOOo0:Llyiahf/vczjk/lo4;

    iput-object p1, p0, Llyiahf/vczjk/vo4;->OooO0Oo:Llyiahf/vczjk/lo4;

    new-instance p1, Llyiahf/vczjk/kf5;

    invoke-direct {p1, p0}, Llyiahf/vczjk/kf5;-><init>(Llyiahf/vczjk/vo4;)V

    iput-object p1, p0, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    return-void
.end method


# virtual methods
.method public final OooO()V
    .locals 6

    iget-object v0, p0, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iget-object v1, v0, Llyiahf/vczjk/kf5;->OooOooo:Ljava/lang/Object;

    const/4 v2, 0x7

    const/4 v3, 0x0

    iget-object v4, p0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    iget-object v5, v0, Llyiahf/vczjk/kf5;->OooOOo:Llyiahf/vczjk/vo4;

    if-nez v1, :cond_0

    invoke-virtual {v5}, Llyiahf/vczjk/vo4;->OooO00o()Llyiahf/vczjk/v16;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/v16;->OooOoo()Ljava/lang/Object;

    move-result-object v1

    if-nez v1, :cond_0

    goto :goto_0

    :cond_0
    iget-boolean v1, v0, Llyiahf/vczjk/kf5;->OooOooO:Z

    if-nez v1, :cond_1

    goto :goto_0

    :cond_1
    iput-boolean v3, v0, Llyiahf/vczjk/kf5;->OooOooO:Z

    invoke-virtual {v5}, Llyiahf/vczjk/vo4;->OooO00o()Llyiahf/vczjk/v16;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/v16;->OooOoo()Ljava/lang/Object;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/kf5;->OooOooo:Ljava/lang/Object;

    invoke-virtual {v4}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v0

    if-eqz v0, :cond_2

    invoke-static {v0, v3, v2}, Llyiahf/vczjk/ro4;->OoooOOO(Llyiahf/vczjk/ro4;ZI)V

    :cond_2
    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    if-eqz v0, :cond_6

    iget-object v1, v0, Llyiahf/vczjk/w65;->Oooo0O0:Ljava/lang/Object;

    iget-object v5, v0, Llyiahf/vczjk/w65;->OooOOo:Llyiahf/vczjk/vo4;

    if-nez v1, :cond_3

    invoke-virtual {v5}, Llyiahf/vczjk/vo4;->OooO00o()Llyiahf/vczjk/v16;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/v16;->o0000O0()Llyiahf/vczjk/q65;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v1, v1, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    invoke-virtual {v1}, Llyiahf/vczjk/v16;->OooOoo()Ljava/lang/Object;

    move-result-object v1

    if-nez v1, :cond_3

    goto :goto_1

    :cond_3
    iget-boolean v1, v0, Llyiahf/vczjk/w65;->Oooo0:Z

    if-nez v1, :cond_4

    goto :goto_1

    :cond_4
    iput-boolean v3, v0, Llyiahf/vczjk/w65;->Oooo0:Z

    invoke-virtual {v5}, Llyiahf/vczjk/vo4;->OooO00o()Llyiahf/vczjk/v16;

    move-result-object v1

    invoke-virtual {v1}, Llyiahf/vczjk/v16;->o0000O0()Llyiahf/vczjk/q65;

    move-result-object v1

    invoke-static {v1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    iget-object v1, v1, Llyiahf/vczjk/q65;->OooOoO0:Llyiahf/vczjk/v16;

    invoke-virtual {v1}, Llyiahf/vczjk/v16;->OooOoo()Ljava/lang/Object;

    move-result-object v1

    iput-object v1, v0, Llyiahf/vczjk/w65;->Oooo0O0:Ljava/lang/Object;

    invoke-static {v4}, Llyiahf/vczjk/r02;->OooOo0o(Llyiahf/vczjk/ro4;)Z

    move-result v0

    if-eqz v0, :cond_5

    invoke-virtual {v4}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v0

    if-eqz v0, :cond_6

    invoke-static {v0, v3, v2}, Llyiahf/vczjk/ro4;->OoooOOO(Llyiahf/vczjk/ro4;ZI)V

    return-void

    :cond_5
    invoke-virtual {v4}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v0

    if-eqz v0, :cond_6

    invoke-static {v0, v3, v2}, Llyiahf/vczjk/ro4;->OoooOO0(Llyiahf/vczjk/ro4;ZI)V

    :cond_6
    :goto_1
    return-void
.end method

.method public final OooO00o()Llyiahf/vczjk/v16;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OoooO0:Llyiahf/vczjk/jb0;

    iget-object v0, v0, Llyiahf/vczjk/jb0;->OooO0Oo:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/v16;

    return-object v0
.end method

.method public final OooO0O0()V
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooO0Oo:Llyiahf/vczjk/lo4;

    sget-object v1, Llyiahf/vczjk/lo4;->OooOOOO:Llyiahf/vczjk/lo4;

    const/4 v2, 0x1

    if-eq v0, v1, :cond_0

    sget-object v1, Llyiahf/vczjk/lo4;->OooOOOo:Llyiahf/vczjk/lo4;

    if-ne v0, v1, :cond_2

    :cond_0
    iget-object v1, p0, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    iget-boolean v1, v1, Llyiahf/vczjk/kf5;->Oooo0oO:Z

    if-eqz v1, :cond_1

    invoke-virtual {p0, v2}, Llyiahf/vczjk/vo4;->OooO0o(Z)V

    goto :goto_0

    :cond_1
    invoke-virtual {p0, v2}, Llyiahf/vczjk/vo4;->OooO0o0(Z)V

    :cond_2
    :goto_0
    sget-object v1, Llyiahf/vczjk/lo4;->OooOOOo:Llyiahf/vczjk/lo4;

    if-ne v0, v1, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    if-eqz v0, :cond_3

    iget-boolean v0, v0, Llyiahf/vczjk/w65;->Oooo00o:Z

    if-ne v0, v2, :cond_3

    invoke-virtual {p0, v2}, Llyiahf/vczjk/vo4;->OooO0oo(Z)V

    return-void

    :cond_3
    invoke-virtual {p0, v2}, Llyiahf/vczjk/vo4;->OooO0oO(Z)V

    :cond_4
    return-void
.end method

.method public final OooO0OO(I)V
    .locals 3

    iget v0, p0, Llyiahf/vczjk/vo4;->OooOO0o:I

    iput p1, p0, Llyiahf/vczjk/vo4;->OooOO0o:I

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-nez v0, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    if-nez p1, :cond_1

    move v1, v2

    :cond_1
    if-eq v0, v1, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v0

    if-eqz v0, :cond_2

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    goto :goto_1

    :cond_2
    const/4 v0, 0x0

    :goto_1
    if-eqz v0, :cond_4

    if-nez p1, :cond_3

    iget p1, v0, Llyiahf/vczjk/vo4;->OooOO0o:I

    add-int/lit8 p1, p1, -0x1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/vo4;->OooO0OO(I)V

    return-void

    :cond_3
    iget p1, v0, Llyiahf/vczjk/vo4;->OooOO0o:I

    add-int/2addr p1, v2

    invoke-virtual {v0, p1}, Llyiahf/vczjk/vo4;->OooO0OO(I)V

    :cond_4
    return-void
.end method

.method public final OooO0Oo(I)V
    .locals 3

    iget v0, p0, Llyiahf/vczjk/vo4;->OooOOOO:I

    iput p1, p0, Llyiahf/vczjk/vo4;->OooOOOO:I

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-nez v0, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    if-nez p1, :cond_1

    move v1, v2

    :cond_1
    if-eq v0, v1, :cond_4

    iget-object v0, p0, Llyiahf/vczjk/vo4;->OooO00o:Llyiahf/vczjk/ro4;

    invoke-virtual {v0}, Llyiahf/vczjk/ro4;->OooOo0O()Llyiahf/vczjk/ro4;

    move-result-object v0

    if-eqz v0, :cond_2

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    goto :goto_1

    :cond_2
    const/4 v0, 0x0

    :goto_1
    if-eqz v0, :cond_4

    if-nez p1, :cond_3

    iget p1, v0, Llyiahf/vczjk/vo4;->OooOOOO:I

    add-int/lit8 p1, p1, -0x1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/vo4;->OooO0Oo(I)V

    return-void

    :cond_3
    iget p1, v0, Llyiahf/vczjk/vo4;->OooOOOO:I

    add-int/2addr p1, v2

    invoke-virtual {v0, p1}, Llyiahf/vczjk/vo4;->OooO0Oo(I)V

    :cond_4
    return-void
.end method

.method public final OooO0o(Z)V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/vo4;->OooOO0:Z

    if-eq v0, p1, :cond_1

    iput-boolean p1, p0, Llyiahf/vczjk/vo4;->OooOO0:Z

    if-eqz p1, :cond_0

    iget-boolean v0, p0, Llyiahf/vczjk/vo4;->OooOO0O:Z

    if-nez v0, :cond_0

    iget p1, p0, Llyiahf/vczjk/vo4;->OooOO0o:I

    add-int/lit8 p1, p1, 0x1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/vo4;->OooO0OO(I)V

    return-void

    :cond_0
    if-nez p1, :cond_1

    iget-boolean p1, p0, Llyiahf/vczjk/vo4;->OooOO0O:Z

    if-nez p1, :cond_1

    iget p1, p0, Llyiahf/vczjk/vo4;->OooOO0o:I

    add-int/lit8 p1, p1, -0x1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/vo4;->OooO0OO(I)V

    :cond_1
    return-void
.end method

.method public final OooO0o0(Z)V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/vo4;->OooOO0O:Z

    if-eq v0, p1, :cond_1

    iput-boolean p1, p0, Llyiahf/vczjk/vo4;->OooOO0O:Z

    if-eqz p1, :cond_0

    iget-boolean v0, p0, Llyiahf/vczjk/vo4;->OooOO0:Z

    if-nez v0, :cond_0

    iget p1, p0, Llyiahf/vczjk/vo4;->OooOO0o:I

    add-int/lit8 p1, p1, 0x1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/vo4;->OooO0OO(I)V

    return-void

    :cond_0
    if-nez p1, :cond_1

    iget-boolean p1, p0, Llyiahf/vczjk/vo4;->OooOO0:Z

    if-nez p1, :cond_1

    iget p1, p0, Llyiahf/vczjk/vo4;->OooOO0o:I

    add-int/lit8 p1, p1, -0x1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/vo4;->OooO0OO(I)V

    :cond_1
    return-void
.end method

.method public final OooO0oO(Z)V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/vo4;->OooOOO:Z

    if-eq v0, p1, :cond_1

    iput-boolean p1, p0, Llyiahf/vczjk/vo4;->OooOOO:Z

    if-eqz p1, :cond_0

    iget-boolean v0, p0, Llyiahf/vczjk/vo4;->OooOOO0:Z

    if-nez v0, :cond_0

    iget p1, p0, Llyiahf/vczjk/vo4;->OooOOOO:I

    add-int/lit8 p1, p1, 0x1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/vo4;->OooO0Oo(I)V

    return-void

    :cond_0
    if-nez p1, :cond_1

    iget-boolean p1, p0, Llyiahf/vczjk/vo4;->OooOOO0:Z

    if-nez p1, :cond_1

    iget p1, p0, Llyiahf/vczjk/vo4;->OooOOOO:I

    add-int/lit8 p1, p1, -0x1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/vo4;->OooO0Oo(I)V

    :cond_1
    return-void
.end method

.method public final OooO0oo(Z)V
    .locals 1

    iget-boolean v0, p0, Llyiahf/vczjk/vo4;->OooOOO0:Z

    if-eq v0, p1, :cond_1

    iput-boolean p1, p0, Llyiahf/vczjk/vo4;->OooOOO0:Z

    if-eqz p1, :cond_0

    iget-boolean v0, p0, Llyiahf/vczjk/vo4;->OooOOO:Z

    if-nez v0, :cond_0

    iget p1, p0, Llyiahf/vczjk/vo4;->OooOOOO:I

    add-int/lit8 p1, p1, 0x1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/vo4;->OooO0Oo(I)V

    return-void

    :cond_0
    if-nez p1, :cond_1

    iget-boolean p1, p0, Llyiahf/vczjk/vo4;->OooOOO:Z

    if-nez p1, :cond_1

    iget p1, p0, Llyiahf/vczjk/vo4;->OooOOOO:I

    add-int/lit8 p1, p1, -0x1

    invoke-virtual {p0, p1}, Llyiahf/vczjk/vo4;->OooO0Oo(I)V

    :cond_1
    return-void
.end method

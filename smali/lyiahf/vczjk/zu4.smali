.class public final Llyiahf/vczjk/zu4;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ne8;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/hh4;

.field public OooOoo:Llyiahf/vczjk/nf6;

.field public OooOoo0:Llyiahf/vczjk/ru4;

.field public OooOooO:Z

.field public OooOooo:Z

.field public Oooo000:Llyiahf/vczjk/b98;

.field public final Oooo00O:Llyiahf/vczjk/uu4;

.field public Oooo00o:Llyiahf/vczjk/yu4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hh4;Llyiahf/vczjk/ru4;Llyiahf/vczjk/nf6;ZZ)V
    .locals 0

    invoke-direct {p0}, Llyiahf/vczjk/jl5;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/zu4;->OooOoOO:Llyiahf/vczjk/hh4;

    iput-object p2, p0, Llyiahf/vczjk/zu4;->OooOoo0:Llyiahf/vczjk/ru4;

    iput-object p3, p0, Llyiahf/vczjk/zu4;->OooOoo:Llyiahf/vczjk/nf6;

    iput-boolean p4, p0, Llyiahf/vczjk/zu4;->OooOooO:Z

    iput-boolean p5, p0, Llyiahf/vczjk/zu4;->OooOooo:Z

    new-instance p1, Llyiahf/vczjk/uu4;

    invoke-direct {p1, p0}, Llyiahf/vczjk/uu4;-><init>(Llyiahf/vczjk/zu4;)V

    iput-object p1, p0, Llyiahf/vczjk/zu4;->Oooo00O:Llyiahf/vczjk/uu4;

    invoke-virtual {p0}, Llyiahf/vczjk/zu4;->o00000OO()V

    return-void
.end method


# virtual methods
.method public final OooooO0(Llyiahf/vczjk/af8;)V
    .locals 6

    invoke-static {p1}, Llyiahf/vczjk/ye8;->OooO0oO(Llyiahf/vczjk/af8;)V

    iget-object v0, p0, Llyiahf/vczjk/zu4;->Oooo00O:Llyiahf/vczjk/uu4;

    sget-object v1, Llyiahf/vczjk/ve8;->Oooo0OO:Llyiahf/vczjk/ze8;

    move-object v2, p1

    check-cast v2, Llyiahf/vczjk/je8;

    invoke-virtual {v2, v1, v0}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/zu4;->OooOoo:Llyiahf/vczjk/nf6;

    sget-object v1, Llyiahf/vczjk/nf6;->OooOOO0:Llyiahf/vczjk/nf6;

    const/4 v3, 0x0

    const-string v4, "scrollAxisRange"

    if-ne v0, v1, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/zu4;->Oooo000:Llyiahf/vczjk/b98;

    if-eqz v0, :cond_0

    sget-object v1, Llyiahf/vczjk/ve8;->OooOo00:Llyiahf/vczjk/ze8;

    sget-object v4, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    const/16 v5, 0xb

    aget-object v4, v4, v5

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    goto :goto_0

    :cond_0
    invoke-static {v4}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v3

    :cond_1
    iget-object v0, p0, Llyiahf/vczjk/zu4;->Oooo000:Llyiahf/vczjk/b98;

    if-eqz v0, :cond_3

    sget-object v1, Llyiahf/vczjk/ve8;->OooOOoo:Llyiahf/vczjk/ze8;

    sget-object v4, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    const/16 v5, 0xa

    aget-object v4, v4, v5

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    :goto_0
    iget-object v0, p0, Llyiahf/vczjk/zu4;->Oooo00o:Llyiahf/vczjk/yu4;

    if-eqz v0, :cond_2

    sget-object v1, Llyiahf/vczjk/ie8;->OooO0o:Llyiahf/vczjk/ze8;

    new-instance v4, Llyiahf/vczjk/o0O00O;

    invoke-direct {v4, v3, v0}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v2, v1, v4}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    :cond_2
    new-instance v0, Llyiahf/vczjk/tu4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/tu4;-><init>(Llyiahf/vczjk/zu4;)V

    sget-object v1, Llyiahf/vczjk/ie8;->OooOoo0:Llyiahf/vczjk/ze8;

    new-instance v4, Llyiahf/vczjk/o0O00O;

    new-instance v5, Llyiahf/vczjk/xe8;

    invoke-direct {v5, v0}, Llyiahf/vczjk/xe8;-><init>(Llyiahf/vczjk/tu4;)V

    invoke-direct {v4, v3, v5}, Llyiahf/vczjk/o0O00O;-><init>(Ljava/lang/String;Llyiahf/vczjk/cf3;)V

    invoke-virtual {v2, v1, v4}, Llyiahf/vczjk/je8;->OooO0oo(Llyiahf/vczjk/ze8;Ljava/lang/Object;)V

    iget-object v0, p0, Llyiahf/vczjk/zu4;->OooOoo0:Llyiahf/vczjk/ru4;

    invoke-interface {v0}, Llyiahf/vczjk/ru4;->OooO0o()Llyiahf/vczjk/v11;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/ve8;->OooO0o:Llyiahf/vczjk/ze8;

    sget-object v2, Llyiahf/vczjk/ye8;->OooO00o:[Llyiahf/vczjk/th4;

    const/16 v3, 0x15

    aget-object v2, v2, v3

    invoke-virtual {v1, p1, v0}, Llyiahf/vczjk/ze8;->OooO00o(Llyiahf/vczjk/af8;Ljava/lang/Object;)V

    return-void

    :cond_3
    invoke-static {v4}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v3
.end method

.method public final o00000OO()V
    .locals 4

    new-instance v0, Llyiahf/vczjk/b98;

    new-instance v1, Llyiahf/vczjk/vu4;

    invoke-direct {v1, p0}, Llyiahf/vczjk/vu4;-><init>(Llyiahf/vczjk/zu4;)V

    new-instance v2, Llyiahf/vczjk/wu4;

    invoke-direct {v2, p0}, Llyiahf/vczjk/wu4;-><init>(Llyiahf/vczjk/zu4;)V

    iget-boolean v3, p0, Llyiahf/vczjk/zu4;->OooOooo:Z

    invoke-direct {v0, v1, v2, v3}, Llyiahf/vczjk/b98;-><init>(Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Z)V

    iput-object v0, p0, Llyiahf/vczjk/zu4;->Oooo000:Llyiahf/vczjk/b98;

    iget-boolean v0, p0, Llyiahf/vczjk/zu4;->OooOooO:Z

    if-eqz v0, :cond_0

    new-instance v0, Llyiahf/vczjk/yu4;

    invoke-direct {v0, p0}, Llyiahf/vczjk/yu4;-><init>(Llyiahf/vczjk/zu4;)V

    goto :goto_0

    :cond_0
    const/4 v0, 0x0

    :goto_0
    iput-object v0, p0, Llyiahf/vczjk/zu4;->Oooo00o:Llyiahf/vczjk/yu4;

    return-void
.end method

.method public final o0Oo0oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

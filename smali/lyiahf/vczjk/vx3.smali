.class public final Llyiahf/vczjk/vx3;
.super Llyiahf/vczjk/m52;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ug1;


# instance fields
.field public OooOoo:Z

.field public OooOooO:Llyiahf/vczjk/n24;

.field public OooOooo:F

.field public Oooo0:Llyiahf/vczjk/ei9;

.field public Oooo000:F

.field public Oooo00O:Z

.field public Oooo00o:Llyiahf/vczjk/r09;

.field public Oooo0O0:Llyiahf/vczjk/gi;

.field public Oooo0OO:Llyiahf/vczjk/qj8;

.field public final Oooo0o:Llyiahf/vczjk/rm0;

.field public final Oooo0o0:Llyiahf/vczjk/gi;


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/n24;Llyiahf/vczjk/ei9;Llyiahf/vczjk/qj8;)V
    .locals 2

    sget v0, Llyiahf/vczjk/li9;->OooO0o0:F

    sget v1, Llyiahf/vczjk/li9;->OooO0Oo:F

    invoke-direct {p0}, Llyiahf/vczjk/m52;-><init>()V

    iput-boolean p1, p0, Llyiahf/vczjk/vx3;->OooOoo:Z

    iput-object p2, p0, Llyiahf/vczjk/vx3;->OooOooO:Llyiahf/vczjk/n24;

    iput v0, p0, Llyiahf/vczjk/vx3;->OooOooo:F

    iput v1, p0, Llyiahf/vczjk/vx3;->Oooo000:F

    iput-object p3, p0, Llyiahf/vczjk/vx3;->Oooo0:Llyiahf/vczjk/ei9;

    iput-object p4, p0, Llyiahf/vczjk/vx3;->Oooo0OO:Llyiahf/vczjk/qj8;

    new-instance p2, Llyiahf/vczjk/gi;

    iget-boolean p3, p0, Llyiahf/vczjk/vx3;->Oooo00O:Z

    if-eqz p3, :cond_0

    if-eqz p1, :cond_0

    goto :goto_0

    :cond_0
    move v0, v1

    :goto_0
    new-instance p1, Llyiahf/vczjk/wd2;

    invoke-direct {p1, v0}, Llyiahf/vczjk/wd2;-><init>(F)V

    sget-object p3, Llyiahf/vczjk/gda;->OooO0OO:Llyiahf/vczjk/n1a;

    const/4 p4, 0x0

    const/16 v0, 0xc

    invoke-direct {p2, p1, p3, p4, v0}, Llyiahf/vczjk/gi;-><init>(Ljava/lang/Object;Llyiahf/vczjk/n1a;Ljava/lang/Object;I)V

    iput-object p2, p0, Llyiahf/vczjk/vx3;->Oooo0o0:Llyiahf/vczjk/gi;

    new-instance p1, Llyiahf/vczjk/o000OO;

    const/16 p2, 0x1a

    invoke-direct {p1, p0, p2}, Llyiahf/vczjk/o000OO;-><init>(Ljava/lang/Object;I)V

    new-instance p2, Llyiahf/vczjk/rm0;

    new-instance p3, Llyiahf/vczjk/tm0;

    invoke-direct {p3}, Llyiahf/vczjk/tm0;-><init>()V

    invoke-direct {p2, p3, p1}, Llyiahf/vczjk/rm0;-><init>(Llyiahf/vczjk/tm0;Llyiahf/vczjk/oe3;)V

    invoke-virtual {p0, p2}, Llyiahf/vczjk/m52;->o00000OO(Llyiahf/vczjk/l52;)Llyiahf/vczjk/l52;

    iput-object p2, p0, Llyiahf/vczjk/vx3;->Oooo0o:Llyiahf/vczjk/rm0;

    return-void
.end method

.method public static final o0000Ooo(Llyiahf/vczjk/vx3;Llyiahf/vczjk/eb9;)Ljava/lang/Object;
    .locals 4

    const/4 v0, 0x0

    iput-boolean v0, p0, Llyiahf/vczjk/vx3;->Oooo00O:Z

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iget-object v1, p0, Llyiahf/vczjk/vx3;->OooOooO:Llyiahf/vczjk/n24;

    invoke-interface {v1}, Llyiahf/vczjk/n24;->OooO00o()Llyiahf/vczjk/f43;

    move-result-object v1

    new-instance v2, Llyiahf/vczjk/tx3;

    const/4 v3, 0x0

    invoke-direct {v2, v3, v0, p0}, Llyiahf/vczjk/tx3;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    invoke-interface {v1, v2, p1}, Llyiahf/vczjk/f43;->OooO00o(Llyiahf/vczjk/h43;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p0

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p0, p1, :cond_0

    return-object p0

    :cond_0
    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0
.end method


# virtual methods
.method public final o00000oO()V
    .locals 4

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/qx3;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/qx3;-><init>(Llyiahf/vczjk/vx3;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x3

    invoke-static {v0, v2, v2, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/rx3;

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/rx3;-><init>(Llyiahf/vczjk/vx3;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, v2, v2, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    return-void
.end method

.method public final o0O0O00()V
    .locals 6

    invoke-virtual {p0}, Llyiahf/vczjk/jl5;->o0OOO0o()Llyiahf/vczjk/xr1;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/sx3;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Llyiahf/vczjk/sx3;-><init>(Llyiahf/vczjk/vx3;Llyiahf/vczjk/yo1;)V

    const/4 v3, 0x3

    invoke-static {v0, v2, v2, v1, v3}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/vx3;->Oooo00o:Llyiahf/vczjk/r09;

    iget-object v0, p0, Llyiahf/vczjk/vx3;->Oooo0O0:Llyiahf/vczjk/gi;

    if-nez v0, :cond_1

    iget-object v0, p0, Llyiahf/vczjk/vx3;->Oooo0:Llyiahf/vczjk/ei9;

    if-nez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/li9;->OooO00o:Llyiahf/vczjk/li9;

    sget-object v0, Llyiahf/vczjk/z21;->OooO00o:Llyiahf/vczjk/l39;

    invoke-static {p0, v0}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/x21;

    sget-object v1, Llyiahf/vczjk/jn9;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-static {p0, v1}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/in9;

    invoke-static {v0, v1}, Llyiahf/vczjk/li9;->OooO0OO(Llyiahf/vczjk/x21;Llyiahf/vczjk/in9;)Llyiahf/vczjk/ei9;

    move-result-object v0

    :cond_0
    iget-boolean v1, p0, Llyiahf/vczjk/vx3;->OooOoo:Z

    const/4 v3, 0x0

    iget-boolean v4, p0, Llyiahf/vczjk/vx3;->Oooo00O:Z

    invoke-virtual {v0, v1, v3, v4}, Llyiahf/vczjk/ei9;->OooO0OO(ZZZ)J

    move-result-wide v0

    new-instance v3, Llyiahf/vczjk/gi;

    new-instance v4, Llyiahf/vczjk/n21;

    invoke-direct {v4, v0, v1}, Llyiahf/vczjk/n21;-><init>(J)V

    invoke-static {v0, v1}, Llyiahf/vczjk/n21;->OooO0o(J)Llyiahf/vczjk/a31;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/ke0;->OooOOoo:Llyiahf/vczjk/ke0;

    new-instance v5, Llyiahf/vczjk/i31;

    invoke-direct {v5, v0}, Llyiahf/vczjk/i31;-><init>(Llyiahf/vczjk/a31;)V

    sget-object v0, Llyiahf/vczjk/gda;->OooO00o:Llyiahf/vczjk/n1a;

    new-instance v0, Llyiahf/vczjk/n1a;

    invoke-direct {v0, v1, v5}, Llyiahf/vczjk/n1a;-><init>(Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V

    const/16 v1, 0xc

    invoke-direct {v3, v4, v0, v2, v1}, Llyiahf/vczjk/gi;-><init>(Ljava/lang/Object;Llyiahf/vczjk/n1a;Ljava/lang/Object;I)V

    iput-object v3, p0, Llyiahf/vczjk/vx3;->Oooo0O0:Llyiahf/vczjk/gi;

    :cond_1
    return-void
.end method

.method public final o0Oo0oo()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

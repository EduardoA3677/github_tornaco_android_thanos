.class public final Llyiahf/vczjk/ki2;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/h1a;

.field public final OooO0O0:Llyiahf/vczjk/c9;

.field public final OooO0OO:Llyiahf/vczjk/qs5;

.field public OooO0Oo:Llyiahf/vczjk/p13;

.field public OooO0o0:Llyiahf/vczjk/p13;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/mi2;Llyiahf/vczjk/oe3;)V
    .locals 7

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    sget-object v0, Llyiahf/vczjk/yx5;->OooO0OO:Llyiahf/vczjk/h1a;

    iput-object v0, p0, Llyiahf/vczjk/ki2;->OooO00o:Llyiahf/vczjk/h1a;

    new-instance v1, Llyiahf/vczjk/c9;

    new-instance v3, Llyiahf/vczjk/ow;

    const/16 v0, 0x18

    invoke-direct {v3, v0}, Llyiahf/vczjk/ow;-><init>(I)V

    new-instance v4, Llyiahf/vczjk/ei2;

    const/4 v0, 0x0

    invoke-direct {v4, p0, v0}, Llyiahf/vczjk/ei2;-><init>(Llyiahf/vczjk/ki2;I)V

    new-instance v5, Llyiahf/vczjk/ei2;

    const/4 v0, 0x1

    invoke-direct {v5, p0, v0}, Llyiahf/vczjk/ei2;-><init>(Llyiahf/vczjk/ki2;I)V

    move-object v2, p1

    move-object v6, p2

    invoke-direct/range {v1 .. v6}, Llyiahf/vczjk/c9;-><init>(Ljava/lang/Enum;Llyiahf/vczjk/oe3;Llyiahf/vczjk/le3;Llyiahf/vczjk/le3;Llyiahf/vczjk/oe3;)V

    iput-object v1, p0, Llyiahf/vczjk/ki2;->OooO0O0:Llyiahf/vczjk/c9;

    const/4 p1, 0x0

    invoke-static {p1}, Landroidx/compose/runtime/OooO0o;->OooOO0(Ljava/lang/Object;)Llyiahf/vczjk/qs5;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ki2;->OooO0OO:Llyiahf/vczjk/qs5;

    invoke-static {}, Llyiahf/vczjk/ng0;->OoooOOo()Llyiahf/vczjk/ev8;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ki2;->OooO0Oo:Llyiahf/vczjk/p13;

    invoke-static {}, Llyiahf/vczjk/ng0;->OoooOOo()Llyiahf/vczjk/ev8;

    move-result-object p1

    iput-object p1, p0, Llyiahf/vczjk/ki2;->OooO0o0:Llyiahf/vczjk/p13;

    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/ki2;Llyiahf/vczjk/mi2;Llyiahf/vczjk/wl;Llyiahf/vczjk/eb9;)Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/ki2;->OooO0O0:Llyiahf/vczjk/c9;

    iget-object v0, v0, Llyiahf/vczjk/c9;->OooOO0O:Llyiahf/vczjk/lr5;

    check-cast v0, Llyiahf/vczjk/zv8;

    invoke-virtual {v0}, Llyiahf/vczjk/zv8;->OooOOoo()F

    move-result v0

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance v1, Llyiahf/vczjk/ji2;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v0, p2, v2}, Llyiahf/vczjk/ji2;-><init>(Llyiahf/vczjk/ki2;FLlyiahf/vczjk/wl;Llyiahf/vczjk/yo1;)V

    sget-object p2, Llyiahf/vczjk/at5;->OooOOO0:Llyiahf/vczjk/at5;

    iget-object p0, p0, Llyiahf/vczjk/ki2;->OooO0O0:Llyiahf/vczjk/c9;

    invoke-virtual {p0, p1, p2, v1, p3}, Llyiahf/vczjk/c9;->OooO00o(Ljava/lang/Object;Llyiahf/vczjk/at5;Llyiahf/vczjk/df3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p0

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p0, p1, :cond_0

    return-object p0

    :cond_0
    sget-object p0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p0
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/eb9;)Ljava/lang/Object;
    .locals 2

    sget-object v0, Llyiahf/vczjk/mi2;->OooOOO0:Llyiahf/vczjk/mi2;

    iget-object v1, p0, Llyiahf/vczjk/ki2;->OooO0o0:Llyiahf/vczjk/p13;

    invoke-static {p0, v0, v1, p1}, Llyiahf/vczjk/ki2;->OooO00o(Llyiahf/vczjk/ki2;Llyiahf/vczjk/mi2;Llyiahf/vczjk/wl;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, v0, :cond_0

    return-object p1

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

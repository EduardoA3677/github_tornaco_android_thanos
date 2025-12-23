.class public final Llyiahf/vczjk/ra4;
.super Llyiahf/vczjk/m80;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/ra4;

.field private static final serialVersionUID:J = 0x1L


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/ra4;

    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    const-class v2, Llyiahf/vczjk/ky;

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/m80;-><init>(Ljava/lang/Class;Ljava/lang/Boolean;)V

    sput-object v0, Llyiahf/vczjk/ra4;->OooOOOO:Llyiahf/vczjk/ra4;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 1

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0Oo0oo()Llyiahf/vczjk/ua4;

    move-result-object v0

    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/m80;->OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/ky;

    move-result-object p1

    return-object p1

    :cond_0
    const-class v0, Llyiahf/vczjk/ky;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p3, Llyiahf/vczjk/ky;

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o0()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/m80;->OooooO0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ky;)V

    return-object p3

    :cond_0
    const-class p3, Llyiahf/vczjk/ky;

    invoke-virtual {p2, p3, p1}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    const/4 p1, 0x0

    throw p1
.end method

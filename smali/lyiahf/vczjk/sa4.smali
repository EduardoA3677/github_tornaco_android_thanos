.class public final Llyiahf/vczjk/sa4;
.super Llyiahf/vczjk/m80;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/sa4;

.field private static final serialVersionUID:J = 0x1L


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/sa4;

    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    const-class v2, Llyiahf/vczjk/f76;

    invoke-direct {v0, v2, v1}, Llyiahf/vczjk/m80;-><init>(Ljava/lang/Class;Ljava/lang/Boolean;)V

    sput-object v0, Llyiahf/vczjk/sa4;->OooOOOO:Llyiahf/vczjk/sa4;

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 1

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->o0000o0O()Z

    move-result v0

    if-eqz v0, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0Oo0oo()Llyiahf/vczjk/ua4;

    move-result-object v0

    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/m80;->Ooooo00(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/f76;

    move-result-object p1

    return-object p1

    :cond_0
    sget-object v0, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v0

    if-eqz v0, :cond_1

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0Oo0oo()Llyiahf/vczjk/ua4;

    move-result-object v0

    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/m80;->Ooooo0o(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/f76;

    move-result-object p1

    return-object p1

    :cond_1
    sget-object v0, Llyiahf/vczjk/gc4;->OooOOOO:Llyiahf/vczjk/gc4;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v0

    if-eqz v0, :cond_2

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0Oo0oo()Llyiahf/vczjk/ua4;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    new-instance p2, Llyiahf/vczjk/f76;

    invoke-direct {p2, p1}, Llyiahf/vczjk/f76;-><init>(Llyiahf/vczjk/ua4;)V

    return-object p2

    :cond_2
    const-class v0, Llyiahf/vczjk/f76;

    invoke-virtual {p1, v0, p2}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    const/4 p1, 0x0

    throw p1
.end method

.method public final OooO0o0(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p3, Llyiahf/vczjk/f76;

    invoke-virtual {p1}, Llyiahf/vczjk/eb4;->o0000o0O()Z

    move-result v0

    if-nez v0, :cond_1

    sget-object v0, Llyiahf/vczjk/gc4;->OooOOo:Llyiahf/vczjk/gc4;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/eb4;->o0000Oo(Llyiahf/vczjk/gc4;)Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    const-class p3, Llyiahf/vczjk/f76;

    invoke-virtual {p2, p3, p1}, Llyiahf/vczjk/v72;->o000000o(Ljava/lang/Class;Llyiahf/vczjk/eb4;)V

    const/4 p1, 0x0

    throw p1

    :cond_1
    :goto_0
    invoke-virtual {p0, p1, p2, p3}, Llyiahf/vczjk/m80;->OooooOO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/f76;)Llyiahf/vczjk/qa4;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/f76;

    return-object p1
.end method

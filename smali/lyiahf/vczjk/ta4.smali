.class public final Llyiahf/vczjk/ta4;
.super Llyiahf/vczjk/m80;
.source "SourceFile"


# static fields
.field public static final OooOOOO:Llyiahf/vczjk/ta4;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/ta4;

    const-class v1, Llyiahf/vczjk/qa4;

    const/4 v2, 0x0

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/m80;-><init>(Ljava/lang/Class;Ljava/lang/Boolean;)V

    sput-object v0, Llyiahf/vczjk/ta4;->OooOOOO:Llyiahf/vczjk/ta4;

    return-void
.end method


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 0

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0Oo0oo()Llyiahf/vczjk/ua4;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object p1, Llyiahf/vczjk/p46;->OooOOO0:Llyiahf/vczjk/p46;

    return-object p1
.end method

.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 2

    invoke-virtual {p2}, Llyiahf/vczjk/eb4;->OooOoO()I

    move-result v0

    const/4 v1, 0x1

    if-eq v0, v1, :cond_1

    const/4 v1, 0x3

    if-eq v0, v1, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0Oo0oo()Llyiahf/vczjk/ua4;

    move-result-object v0

    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/m80;->OoooOoO(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/qa4;

    move-result-object p1

    return-object p1

    :cond_0
    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0Oo0oo()Llyiahf/vczjk/ua4;

    move-result-object v0

    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/m80;->OoooOoo(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/ky;

    move-result-object p1

    return-object p1

    :cond_1
    invoke-virtual {p1}, Llyiahf/vczjk/v72;->o0Oo0oo()Llyiahf/vczjk/ua4;

    move-result-object v0

    invoke-virtual {p0, p2, p1, v0}, Llyiahf/vczjk/m80;->Ooooo00(Llyiahf/vczjk/eb4;Llyiahf/vczjk/v72;Llyiahf/vczjk/ua4;)Llyiahf/vczjk/f76;

    move-result-object p1

    return-object p1
.end method

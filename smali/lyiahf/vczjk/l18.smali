.class public final Llyiahf/vczjk/l18;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $isDOL:Z

.field synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(ZLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-boolean p1, p0, Llyiahf/vczjk/l18;->$isDOL:Z

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/l18;

    iget-boolean v1, p0, Llyiahf/vczjk/l18;->$isDOL:Z

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/l18;-><init>(ZLlyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/l18;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/l18;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/l18;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/l18;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/l18;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/l18;->L$0:Ljava/lang/Object;

    check-cast p1, Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;

    invoke-static {p1}, Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;->newBuilder(Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;)Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings$Builder;

    move-result-object p1

    iget-boolean v0, p0, Llyiahf/vczjk/l18;->$isDOL:Z

    xor-int/lit8 v0, v0, 0x1

    invoke-virtual {p1, v0}, Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings$Builder;->setIsDisableDOL(Z)Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings$Builder;

    move-result-object p1

    invoke-virtual {p1}, Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings$Builder;->build()Ltornaco/apps/thanox/core/proto/common/SmartFreezeSettings;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

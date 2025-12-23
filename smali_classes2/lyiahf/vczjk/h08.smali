.class public final Llyiahf/vczjk/h08;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $installStubApkDialog:Llyiahf/vczjk/yg5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/yg5;"
        }
    .end annotation
.end field

.field synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yg5;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/h08;->$installStubApkDialog:Llyiahf/vczjk/yg5;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance v0, Llyiahf/vczjk/h08;

    iget-object v1, p0, Llyiahf/vczjk/h08;->$installStubApkDialog:Llyiahf/vczjk/yg5;

    invoke-direct {v0, v1, p2}, Llyiahf/vczjk/h08;-><init>(Llyiahf/vczjk/yg5;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/h08;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/l79;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/h08;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/h08;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/h08;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p2
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/h08;->label:I

    if-nez v0, :cond_1

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/h08;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/l79;

    instance-of v0, p1, Llyiahf/vczjk/l79;

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/h08;->$installStubApkDialog:Llyiahf/vczjk/yg5;

    iget-object p1, p1, Llyiahf/vczjk/l79;->OooO00o:Ljava/io/File;

    iput-object p1, v0, Llyiahf/vczjk/yg5;->OooO0o:Ljava/lang/Object;

    const/4 p1, 0x1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_0
    new-instance p1, Llyiahf/vczjk/k61;

    invoke-direct {p1}, Ljava/lang/RuntimeException;-><init>()V

    throw p1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

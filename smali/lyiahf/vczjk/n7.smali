.class public final Llyiahf/vczjk/n7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $state:Llyiahf/vczjk/c9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/c9;"
        }
    .end annotation
.end field

.field synthetic F$0:F

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/c9;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/n7;->$state:Llyiahf/vczjk/c9;

    const/4 p1, 0x3

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    move-result p2

    check-cast p3, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/n7;

    iget-object v1, p0, Llyiahf/vczjk/n7;->$state:Llyiahf/vczjk/c9;

    invoke-direct {v0, v1, p3}, Llyiahf/vczjk/n7;-><init>(Llyiahf/vczjk/c9;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/n7;->L$0:Ljava/lang/Object;

    iput p2, v0, Llyiahf/vczjk/n7;->F$0:F

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/n7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/n7;->label:I

    if-nez v0, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/n7;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    iget v0, p0, Llyiahf/vczjk/n7;->F$0:F

    new-instance v1, Llyiahf/vczjk/l7;

    iget-object v2, p0, Llyiahf/vczjk/n7;->$state:Llyiahf/vczjk/c9;

    const/4 v3, 0x0

    invoke-direct {v1, v2, v0, v3}, Llyiahf/vczjk/l7;-><init>(Llyiahf/vczjk/c9;FLlyiahf/vczjk/yo1;)V

    const/4 v0, 0x3

    invoke-static {p1, v3, v3, v1, v0}, Llyiahf/vczjk/os9;->Oooo0O0(Llyiahf/vczjk/xr1;Llyiahf/vczjk/or1;Llyiahf/vczjk/as1;Llyiahf/vczjk/ze3;I)Llyiahf/vczjk/r09;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method

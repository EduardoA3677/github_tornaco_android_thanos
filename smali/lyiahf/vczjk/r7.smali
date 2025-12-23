.class public final Llyiahf/vczjk/r7;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/df3;


# instance fields
.field final synthetic $this_animateTo:Llyiahf/vczjk/c9;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/c9;"
        }
    .end annotation
.end field

.field final synthetic $velocity:F

.field private synthetic L$0:Ljava/lang/Object;

.field synthetic L$1:Ljava/lang/Object;

.field synthetic L$2:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/c9;FLlyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/r7;->$this_animateTo:Llyiahf/vczjk/c9;

    iput p2, p0, Llyiahf/vczjk/r7;->$velocity:F

    const/4 p1, 0x4

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final OooO(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    check-cast p1, Llyiahf/vczjk/r8;

    check-cast p2, Llyiahf/vczjk/kb5;

    check-cast p4, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/r7;

    iget-object v1, p0, Llyiahf/vczjk/r7;->$this_animateTo:Llyiahf/vczjk/c9;

    iget v2, p0, Llyiahf/vczjk/r7;->$velocity:F

    invoke-direct {v0, v1, v2, p4}, Llyiahf/vczjk/r7;-><init>(Llyiahf/vczjk/c9;FLlyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/r7;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/r7;->L$1:Ljava/lang/Object;

    iput-object p3, v0, Llyiahf/vczjk/r7;->L$2:Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/r7;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/r7;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/r7;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/r8;

    iget-object v1, p0, Llyiahf/vczjk/r7;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/kb5;

    iget-object v3, p0, Llyiahf/vczjk/r7;->L$2:Ljava/lang/Object;

    invoke-virtual {v1, v3}, Llyiahf/vczjk/kb5;->OooO0Oo(Ljava/lang/Object;)F

    move-result v5

    invoke-static {v5}, Ljava/lang/Float;->isNaN(F)Z

    move-result v1

    if-nez v1, :cond_3

    new-instance v1, Llyiahf/vczjk/el7;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    iget-object v3, p0, Llyiahf/vczjk/r7;->$this_animateTo:Llyiahf/vczjk/c9;

    invoke-virtual {v3}, Llyiahf/vczjk/c9;->OooO0o0()F

    move-result v3

    invoke-static {v3}, Ljava/lang/Float;->isNaN(F)Z

    move-result v3

    if-eqz v3, :cond_2

    const/4 v3, 0x0

    :goto_0
    move v4, v3

    goto :goto_1

    :cond_2
    iget-object v3, p0, Llyiahf/vczjk/r7;->$this_animateTo:Llyiahf/vczjk/c9;

    invoke-virtual {v3}, Llyiahf/vczjk/c9;->OooO0o0()F

    move-result v3

    goto :goto_0

    :goto_1
    iput v4, v1, Llyiahf/vczjk/el7;->element:F

    iget v6, p0, Llyiahf/vczjk/r7;->$velocity:F

    iget-object v3, p0, Llyiahf/vczjk/r7;->$this_animateTo:Llyiahf/vczjk/c9;

    iget-object v3, v3, Llyiahf/vczjk/c9;->OooO0OO:Llyiahf/vczjk/le3;

    invoke-interface {v3}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    move-result-object v3

    move-object v7, v3

    check-cast v7, Llyiahf/vczjk/wl;

    new-instance v8, Llyiahf/vczjk/p7;

    const/4 v3, 0x0

    invoke-direct {v8, p1, v1, v3}, Llyiahf/vczjk/p7;-><init>(Llyiahf/vczjk/r8;Llyiahf/vczjk/el7;I)V

    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/r7;->L$0:Ljava/lang/Object;

    iput-object p1, p0, Llyiahf/vczjk/r7;->L$1:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/r7;->label:I

    move-object v9, p0

    invoke-static/range {v4 .. v9}, Llyiahf/vczjk/vc6;->OooO0oo(FFFLlyiahf/vczjk/wl;Llyiahf/vczjk/ze3;Llyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    return-object v0

    :cond_3
    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

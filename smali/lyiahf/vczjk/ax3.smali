.class public final Llyiahf/vczjk/ax3;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field label:I

.field final synthetic this$0:Llyiahf/vczjk/cx3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/cx3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ax3;->this$0:Llyiahf/vczjk/cx3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 1

    new-instance p1, Llyiahf/vczjk/ax3;

    iget-object v0, p0, Llyiahf/vczjk/ax3;->this$0:Llyiahf/vczjk/cx3;

    invoke-direct {p1, v0, p2}, Llyiahf/vczjk/ax3;-><init>(Llyiahf/vczjk/cx3;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/ax3;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/ax3;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ax3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/ax3;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/ax3;->this$0:Llyiahf/vczjk/cx3;

    iget-object v4, p1, Llyiahf/vczjk/cx3;->OoooO0:Llyiahf/vczjk/gi;

    if-nez v4, :cond_2

    goto :goto_1

    :cond_2
    invoke-virtual {v4}, Llyiahf/vczjk/gi;->OooO0Oo()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    move-result p1

    const v1, 0x3ef851ec    # 0.485f

    cmpg-float p1, p1, v1

    const v1, 0x3dcccccd    # 0.1f

    const v5, 0x3f5eb852    # 0.87f

    if-gez p1, :cond_3

    move p1, v5

    move v6, p1

    goto :goto_0

    :cond_3
    move p1, v1

    move v6, v5

    :goto_0
    new-instance v5, Ljava/lang/Float;

    invoke-direct {v5, p1}, Ljava/lang/Float;-><init>(F)V

    sget p1, Llyiahf/vczjk/ea7;->OooO00o:F

    new-instance p1, Llyiahf/vczjk/vj4;

    new-instance v7, Llyiahf/vczjk/uj4;

    invoke-direct {v7}, Llyiahf/vczjk/uj4;-><init>()V

    const/16 v8, 0x1770

    iput v8, v7, Llyiahf/vczjk/uj4;->OooO00o:I

    invoke-static {v6}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v6

    const/16 v9, 0xbb8

    invoke-virtual {v7, v9, v6}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    move-result-object v6

    sget-object v9, Llyiahf/vczjk/ea7;->OooO0o0:Llyiahf/vczjk/cu1;

    iput-object v9, v6, Llyiahf/vczjk/tj4;->OooO0O0:Llyiahf/vczjk/ik2;

    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v1

    invoke-virtual {v7, v8, v1}, Llyiahf/vczjk/uj4;->OooO00o(ILjava/lang/Object;)Llyiahf/vczjk/tj4;

    invoke-direct {p1, v7}, Llyiahf/vczjk/vj4;-><init>(Llyiahf/vczjk/uj4;)V

    const/4 v1, 0x6

    invoke-static {p1, v1}, Llyiahf/vczjk/ng0;->Oooo00O(Llyiahf/vczjk/xj2;I)Llyiahf/vczjk/cy3;

    move-result-object v6

    iget-object p1, p0, Llyiahf/vczjk/ax3;->this$0:Llyiahf/vczjk/cx3;

    new-instance v7, Llyiahf/vczjk/uw3;

    const/4 v1, 0x3

    invoke-direct {v7, p1, v1}, Llyiahf/vczjk/uw3;-><init>(Llyiahf/vczjk/cx3;I)V

    iput v3, p0, Llyiahf/vczjk/ax3;->label:I

    const/4 v9, 0x4

    move-object v8, p0

    invoke-static/range {v4 .. v9}, Llyiahf/vczjk/gi;->OooO0O0(Llyiahf/vczjk/gi;Ljava/lang/Object;Llyiahf/vczjk/wl;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;I)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_4

    return-object v0

    :cond_4
    :goto_1
    return-object v2
.end method

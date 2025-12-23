.class public final Llyiahf/vczjk/hy3;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $toolingOverride:Llyiahf/vczjk/qs5;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/qs5;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/jy3;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/jy3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/hy3;->$toolingOverride:Llyiahf/vczjk/qs5;

    iput-object p2, p0, Llyiahf/vczjk/hy3;->this$0:Llyiahf/vczjk/jy3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/hy3;

    iget-object v1, p0, Llyiahf/vczjk/hy3;->$toolingOverride:Llyiahf/vczjk/qs5;

    iget-object v2, p0, Llyiahf/vczjk/hy3;->this$0:Llyiahf/vczjk/jy3;

    invoke-direct {v0, v1, v2, p2}, Llyiahf/vczjk/hy3;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/jy3;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/hy3;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/hy3;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/hy3;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/hy3;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/hy3;->label:I

    const/4 v2, 0x1

    const/4 v3, 0x2

    if-eqz v1, :cond_2

    if-eq v1, v2, :cond_1

    if-ne v1, v3, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/hy3;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/el7;

    iget-object v4, p0, Llyiahf/vczjk/hy3;->L$0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/xr1;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object p1, v4

    goto :goto_0

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    iget-object v1, p0, Llyiahf/vczjk/hy3;->L$1:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/el7;

    iget-object v4, p0, Llyiahf/vczjk/hy3;->L$0:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/xr1;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object p1, v4

    goto :goto_1

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/hy3;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    new-instance v1, Llyiahf/vczjk/el7;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    const/high16 v4, 0x3f800000    # 1.0f

    iput v4, v1, Llyiahf/vczjk/el7;->element:F

    :cond_3
    :goto_0
    new-instance v4, Llyiahf/vczjk/ey3;

    iget-object v5, p0, Llyiahf/vczjk/hy3;->$toolingOverride:Llyiahf/vczjk/qs5;

    iget-object v6, p0, Llyiahf/vczjk/hy3;->this$0:Llyiahf/vczjk/jy3;

    invoke-direct {v4, v5, v6, v1, p1}, Llyiahf/vczjk/ey3;-><init>(Llyiahf/vczjk/qs5;Llyiahf/vczjk/jy3;Llyiahf/vczjk/el7;Llyiahf/vczjk/xr1;)V

    iput-object p1, p0, Llyiahf/vczjk/hy3;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/hy3;->L$1:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/hy3;->label:I

    invoke-static {v4, p0}, Llyiahf/vczjk/sb;->OoooOOo(Llyiahf/vczjk/oe3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v0, :cond_4

    goto :goto_2

    :cond_4
    :goto_1
    iget v4, v1, Llyiahf/vczjk/el7;->element:F

    const/4 v5, 0x0

    cmpg-float v4, v4, v5

    if-nez v4, :cond_3

    new-instance v4, Llyiahf/vczjk/fy3;

    invoke-direct {v4, p1}, Llyiahf/vczjk/fy3;-><init>(Llyiahf/vczjk/xr1;)V

    invoke-static {v4}, Landroidx/compose/runtime/OooO0o;->OooOO0o(Llyiahf/vczjk/le3;)Llyiahf/vczjk/s48;

    move-result-object v4

    new-instance v5, Llyiahf/vczjk/gy3;

    const/4 v6, 0x0

    invoke-direct {v5, v3, v6}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    iput-object p1, p0, Llyiahf/vczjk/hy3;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/hy3;->L$1:Ljava/lang/Object;

    iput v3, p0, Llyiahf/vczjk/hy3;->label:I

    invoke-static {v4, v5, p0}, Llyiahf/vczjk/rs;->OooOoOO(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object v4

    if-ne v4, v0, :cond_3

    :goto_2
    return-object v0
.end method

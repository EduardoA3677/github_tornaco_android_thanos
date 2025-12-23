.class public final synthetic Llyiahf/vczjk/fb6;
.super Llyiahf/vczjk/wf3;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# static fields
.field public static final OooOOO:Llyiahf/vczjk/fb6;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/fb6;

    const-string v4, "register(Lkotlinx/coroutines/selects/SelectInstance;Ljava/lang/Object;)V"

    const/4 v5, 0x0

    const/4 v1, 0x3

    const-class v2, Llyiahf/vczjk/gb6;

    const-string v3, "register"

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/wf3;-><init>(ILjava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    sput-object v0, Llyiahf/vczjk/fb6;->OooOOO:Llyiahf/vczjk/fb6;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    check-cast p1, Llyiahf/vczjk/gb6;

    check-cast p2, Llyiahf/vczjk/hd8;

    iget-wide v0, p1, Llyiahf/vczjk/gb6;->OooO00o:J

    const-wide/16 v2, 0x0

    cmp-long p3, v0, v2

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-gtz p3, :cond_0

    check-cast p2, Llyiahf/vczjk/gd8;

    iput-object v2, p2, Llyiahf/vczjk/gd8;->OooOOo0:Ljava/lang/Object;

    return-object v2

    :cond_0
    new-instance p3, Llyiahf/vczjk/tm4;

    const/4 v3, 0x5

    invoke-direct {p3, v3, p2, p1}, Llyiahf/vczjk/tm4;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    const-string p1, "null cannot be cast to non-null type kotlinx.coroutines.selects.SelectImplementation<*>"

    invoke-static {p2, p1}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p2, Llyiahf/vczjk/gd8;

    iget-object p1, p2, Llyiahf/vczjk/gd8;->OooOOO0:Llyiahf/vczjk/or1;

    invoke-static {p1}, Llyiahf/vczjk/yi4;->OoooOO0(Llyiahf/vczjk/or1;)Llyiahf/vczjk/b52;

    move-result-object v3

    invoke-interface {v3, v0, v1, p3, p1}, Llyiahf/vczjk/b52;->o00oO0o(JLjava/lang/Runnable;Llyiahf/vczjk/or1;)Llyiahf/vczjk/sc2;

    move-result-object p1

    iput-object p1, p2, Llyiahf/vczjk/gd8;->OooOOOO:Ljava/lang/Object;

    return-object v2
.end method

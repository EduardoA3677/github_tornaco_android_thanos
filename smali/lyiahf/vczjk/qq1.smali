.class public final Llyiahf/vczjk/qq1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/compose/ui/input/pointer/PointerInputEventHandler;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/bi9;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/bi9;Llyiahf/vczjk/mk9;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/qq1;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qq1;->OooOOO:Llyiahf/vczjk/bi9;

    iput-object p2, p0, Llyiahf/vczjk/qq1;->OooOOOO:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/dp5;Llyiahf/vczjk/bi9;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/qq1;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/qq1;->OooOOOO:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/qq1;->OooOOO:Llyiahf/vczjk/bi9;

    return-void
.end method


# virtual methods
.method public final invoke(Llyiahf/vczjk/oy6;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 5

    iget v0, p0, Llyiahf/vczjk/qq1;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/zz0;

    move-object v1, p1

    check-cast v1, Llyiahf/vczjk/nb9;

    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object v1

    iget-object v1, v1, Llyiahf/vczjk/ro4;->Oooo0o:Llyiahf/vczjk/gga;

    invoke-direct {v0, v1}, Llyiahf/vczjk/zz0;-><init>(Llyiahf/vczjk/gga;)V

    new-instance v1, Llyiahf/vczjk/td8;

    const/4 v2, 0x0

    iget-object v3, p0, Llyiahf/vczjk/qq1;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/dp5;

    iget-object v4, p0, Llyiahf/vczjk/qq1;->OooOOO:Llyiahf/vczjk/bi9;

    invoke-direct {v1, v3, v0, v4, v2}, Llyiahf/vczjk/td8;-><init>(Llyiahf/vczjk/dp5;Llyiahf/vczjk/zz0;Llyiahf/vczjk/bi9;Llyiahf/vczjk/yo1;)V

    invoke-static {p1, v1, p2}, Llyiahf/vczjk/u34;->OooO0o0(Llyiahf/vczjk/oy6;Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_0

    goto :goto_0

    :cond_0
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_0
    return-object p1

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/pq1;

    iget-object v1, p0, Llyiahf/vczjk/qq1;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/mk9;

    const/4 v2, 0x0

    iget-object v3, p0, Llyiahf/vczjk/qq1;->OooOOO:Llyiahf/vczjk/bi9;

    invoke-direct {v0, p1, v3, v1, v2}, Llyiahf/vczjk/pq1;-><init>(Llyiahf/vczjk/oy6;Llyiahf/vczjk/bi9;Llyiahf/vczjk/mk9;Llyiahf/vczjk/yo1;)V

    invoke-static {v0, p2}, Llyiahf/vczjk/v34;->Oooo00O(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    sget-object p2, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p1, p2, :cond_1

    goto :goto_1

    :cond_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    :goto_1
    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.class public final Llyiahf/vczjk/lf1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $animationClockStartTime:J

.field final synthetic $className:Ljava/lang/String;

.field final synthetic $methodName:Ljava/lang/String;

.field final synthetic $parameterProvider:Ljava/lang/Class;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/lang/Class<",
            "Ljava/lang/Object;",
            ">;"
        }
    .end annotation
.end field

.field final synthetic $parameterProviderIndex:I

.field final synthetic this$0:Landroidx/compose/ui/tooling/ComposeViewAdapter;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Class;ILandroidx/compose/ui/tooling/ComposeViewAdapter;J)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/lf1;->$className:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/lf1;->$methodName:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/lf1;->$parameterProvider:Ljava/lang/Class;

    iput p4, p0, Llyiahf/vczjk/lf1;->$parameterProviderIndex:I

    iput-object p5, p0, Llyiahf/vczjk/lf1;->this$0:Landroidx/compose/ui/tooling/ComposeViewAdapter;

    iput-wide p6, p0, Llyiahf/vczjk/lf1;->$animationClockStartTime:J

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    const/4 v3, 0x0

    if-eq v0, v1, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    move v0, v3

    :goto_0
    and-int/2addr p2, v2

    move-object v7, p1

    check-cast v7, Llyiahf/vczjk/zf1;

    invoke-virtual {v7, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/lf1;->$className:Ljava/lang/String;

    invoke-virtual {v7, p1}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p1

    iget-object p2, p0, Llyiahf/vczjk/lf1;->$methodName:Ljava/lang/String;

    invoke-virtual {v7, p2}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result p2

    or-int/2addr p1, p2

    invoke-virtual {v7, v7}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    or-int/2addr p1, p2

    iget-object p2, p0, Llyiahf/vczjk/lf1;->$parameterProvider:Ljava/lang/Class;

    invoke-virtual {v7, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    or-int/2addr p1, p2

    iget p2, p0, Llyiahf/vczjk/lf1;->$parameterProviderIndex:I

    invoke-virtual {v7, p2}, Llyiahf/vczjk/zf1;->OooO0o0(I)Z

    move-result p2

    or-int/2addr p1, p2

    iget-object p2, p0, Llyiahf/vczjk/lf1;->this$0:Landroidx/compose/ui/tooling/ComposeViewAdapter;

    invoke-virtual {v7, p2}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p2

    or-int/2addr p1, p2

    iget-object v5, p0, Llyiahf/vczjk/lf1;->$className:Ljava/lang/String;

    iget-object v6, p0, Llyiahf/vczjk/lf1;->$methodName:Ljava/lang/String;

    iget-object v8, p0, Llyiahf/vczjk/lf1;->$parameterProvider:Ljava/lang/Class;

    iget v9, p0, Llyiahf/vczjk/lf1;->$parameterProviderIndex:I

    iget-object v10, p0, Llyiahf/vczjk/lf1;->this$0:Landroidx/compose/ui/tooling/ComposeViewAdapter;

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object p2

    sget-object v0, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez p1, :cond_1

    if-ne p2, v0, :cond_2

    :cond_1
    new-instance v4, Llyiahf/vczjk/kf1;

    invoke-direct/range {v4 .. v10}, Llyiahf/vczjk/kf1;-><init>(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/zf1;Ljava/lang/Class;ILandroidx/compose/ui/tooling/ComposeViewAdapter;)V

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object p2, v4

    :cond_2
    check-cast p2, Llyiahf/vczjk/le3;

    iget-wide v1, p0, Llyiahf/vczjk/lf1;->$animationClockStartTime:J

    const-wide/16 v4, 0x0

    cmp-long p1, v1, v4

    if-ltz p1, :cond_5

    const p1, -0x39aa7c82

    invoke-virtual {v7, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/lf1;->this$0:Landroidx/compose/ui/tooling/ComposeViewAdapter;

    invoke-virtual {v7, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v1

    iget-object v2, p0, Llyiahf/vczjk/lf1;->this$0:Landroidx/compose/ui/tooling/ComposeViewAdapter;

    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v4

    if-nez v1, :cond_3

    if-ne v4, v0, :cond_4

    :cond_3
    new-instance v4, Llyiahf/vczjk/jf1;

    invoke-direct {v4, v2}, Llyiahf/vczjk/jf1;-><init>(Landroidx/compose/ui/tooling/ComposeViewAdapter;)V

    invoke-virtual {v7, v4}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v4, Llyiahf/vczjk/le3;

    new-instance v0, Llyiahf/vczjk/e47;

    invoke-direct {v0}, Llyiahf/vczjk/e47;-><init>()V

    invoke-virtual {p1, v0}, Landroidx/compose/ui/tooling/ComposeViewAdapter;->setClock$ui_tooling_release(Llyiahf/vczjk/e47;)V

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_1

    :cond_5
    const p1, -0x3997c2c5

    invoke-virtual {v7, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v7, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_1
    invoke-interface {p2}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    goto :goto_2

    :cond_6
    invoke-virtual {v7}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_2
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method

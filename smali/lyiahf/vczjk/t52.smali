.class public final Llyiahf/vczjk/t52;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/w52;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/w52;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/t52;->this$0:Llyiahf/vczjk/w52;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/t52;->this$0:Llyiahf/vczjk/w52;

    sget-object v1, Llyiahf/vczjk/au7;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-static {v0, v1}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/vt7;

    iget-object v0, p0, Llyiahf/vczjk/t52;->this$0:Llyiahf/vczjk/w52;

    sget-object v1, Llyiahf/vczjk/lm1;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-static {v0, v1}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/n21;

    iget-wide v0, v0, Llyiahf/vczjk/n21;->OooO00o:J

    iget-object v2, p0, Llyiahf/vczjk/t52;->this$0:Llyiahf/vczjk/w52;

    sget-object v3, Llyiahf/vczjk/m31;->OooO00o:Llyiahf/vczjk/l39;

    invoke-static {v2, v3}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Llyiahf/vczjk/k31;

    invoke-virtual {v2}, Llyiahf/vczjk/k31;->OooO0Oo()Z

    move-result v2

    if-eqz v2, :cond_1

    invoke-static {v0, v1}, Llyiahf/vczjk/v34;->OooooOO(J)F

    move-result v0

    float-to-double v0, v0

    const-wide/high16 v2, 0x3fe0000000000000L    # 0.5

    cmpl-double v0, v0, v2

    if-lez v0, :cond_0

    sget-object v0, Llyiahf/vczjk/au7;->OooO0Oo:Llyiahf/vczjk/st7;

    return-object v0

    :cond_0
    sget-object v0, Llyiahf/vczjk/au7;->OooO0o0:Llyiahf/vczjk/st7;

    return-object v0

    :cond_1
    sget-object v0, Llyiahf/vczjk/au7;->OooO0o:Llyiahf/vczjk/st7;

    return-object v0
.end method

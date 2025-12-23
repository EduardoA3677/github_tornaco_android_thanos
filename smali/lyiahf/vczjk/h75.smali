.class public final Llyiahf/vczjk/h75;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/k75;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/k75;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/h75;->this$0:Llyiahf/vczjk/k75;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/h75;->this$0:Llyiahf/vczjk/k75;

    iget-object v0, v0, Llyiahf/vczjk/k75;->OooOOOo:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/h75;->this$0:Llyiahf/vczjk/k75;

    invoke-virtual {v0}, Llyiahf/vczjk/k75;->OooO0Oo()I

    move-result v0

    rem-int/lit8 v0, v0, 0x2

    if-nez v0, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/h75;->this$0:Llyiahf/vczjk/k75;

    iget-object v0, v0, Llyiahf/vczjk/k75;->OooOOo:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    neg-float v0, v0

    goto :goto_0

    :cond_0
    iget-object v0, p0, Llyiahf/vczjk/h75;->this$0:Llyiahf/vczjk/k75;

    iget-object v0, v0, Llyiahf/vczjk/k75;->OooOOo:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Number;

    invoke-virtual {v0}, Ljava/lang/Number;->floatValue()F

    move-result v0

    :goto_0
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object v0

    return-object v0
.end method

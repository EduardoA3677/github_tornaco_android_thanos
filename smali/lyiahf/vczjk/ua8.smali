.class public final Llyiahf/vczjk/ua8;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/va8;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/va8;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ua8;->this$0:Llyiahf/vczjk/va8;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/ua8;->this$0:Llyiahf/vczjk/va8;

    sget-object v1, Llyiahf/vczjk/rg6;->OooO00o:Llyiahf/vczjk/jh1;

    invoke-static {v0, v1}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/dd;

    iput-object v1, v0, Llyiahf/vczjk/va8;->Oooo0oO:Llyiahf/vczjk/dd;

    iget-object v0, p0, Llyiahf/vczjk/ua8;->this$0:Llyiahf/vczjk/va8;

    iget-object v1, v0, Llyiahf/vczjk/va8;->Oooo0oO:Llyiahf/vczjk/dd;

    if-eqz v1, :cond_0

    new-instance v2, Llyiahf/vczjk/cd;

    iget-object v3, v1, Llyiahf/vczjk/dd;->OooO00o:Landroid/content/Context;

    iget-object v7, v1, Llyiahf/vczjk/dd;->OooO0Oo:Llyiahf/vczjk/di6;

    iget-object v4, v1, Llyiahf/vczjk/dd;->OooO0O0:Llyiahf/vczjk/f62;

    iget-wide v5, v1, Llyiahf/vczjk/dd;->OooO0OO:J

    invoke-direct/range {v2 .. v7}, Llyiahf/vczjk/cd;-><init>(Landroid/content/Context;Llyiahf/vczjk/f62;JLlyiahf/vczjk/di6;)V

    goto :goto_0

    :cond_0
    const/4 v2, 0x0

    :goto_0
    iput-object v2, v0, Llyiahf/vczjk/va8;->Oooo0oo:Llyiahf/vczjk/cd;

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method

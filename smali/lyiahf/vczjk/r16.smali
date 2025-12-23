.class public final Llyiahf/vczjk/r16;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/v16;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/v16;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/r16;->this$0:Llyiahf/vczjk/v16;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/r16;->this$0:Llyiahf/vczjk/v16;

    iget-object v0, v0, Llyiahf/vczjk/v16;->OooOoOO:Llyiahf/vczjk/v16;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/v16;->o0000Oo()V

    :cond_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method

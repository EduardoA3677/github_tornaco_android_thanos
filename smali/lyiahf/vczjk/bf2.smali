.class public final Llyiahf/vczjk/bf2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/kf2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kf2;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/bf2;->this$0:Llyiahf/vczjk/kf2;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/bf2;->this$0:Llyiahf/vczjk/kf2;

    iget-object v0, v0, Llyiahf/vczjk/kf2;->Oooo00O:Llyiahf/vczjk/jj0;

    if-eqz v0, :cond_0

    sget-object v1, Llyiahf/vczjk/je2;->OooO00o:Llyiahf/vczjk/je2;

    invoke-interface {v0, v1}, Llyiahf/vczjk/if8;->OooO0oo(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method

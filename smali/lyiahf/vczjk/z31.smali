.class public final Llyiahf/vczjk/z31;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/g41;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/g41;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/z31;->this$0:Llyiahf/vczjk/g41;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z31;->this$0:Llyiahf/vczjk/g41;

    iget-object v0, v0, Llyiahf/vczjk/g41;->OoooOO0:Llyiahf/vczjk/le3;

    if-eqz v0, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/le3;->OooO00o()Ljava/lang/Object;

    :cond_0
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object v0
.end method

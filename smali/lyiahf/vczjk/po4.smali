.class public final Llyiahf/vczjk/po4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/ro4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ro4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/po4;->this$0:Llyiahf/vczjk/ro4;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget-object v0, p0, Llyiahf/vczjk/po4;->this$0:Llyiahf/vczjk/ro4;

    iget-object v0, v0, Llyiahf/vczjk/ro4;->OoooO0O:Llyiahf/vczjk/vo4;

    iget-object v1, v0, Llyiahf/vczjk/vo4;->OooOOOo:Llyiahf/vczjk/kf5;

    const/4 v2, 0x1

    iput-boolean v2, v1, Llyiahf/vczjk/kf5;->Oooo0o:Z

    iget-object v0, v0, Llyiahf/vczjk/vo4;->OooOOo0:Llyiahf/vczjk/w65;

    if-eqz v0, :cond_0

    iput-boolean v2, v0, Llyiahf/vczjk/w65;->Oooo00O:Z

    :cond_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0
.end method

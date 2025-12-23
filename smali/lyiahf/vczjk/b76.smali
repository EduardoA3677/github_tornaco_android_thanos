.class public final Llyiahf/vczjk/b76;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/c76;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/c76;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/c76;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/b76;->this$0:Llyiahf/vczjk/c76;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b76;->this$0:Llyiahf/vczjk/c76;

    if-ne p1, v0, :cond_0

    const-string p1, "(this)"

    return-object p1

    :cond_0
    invoke-static {p1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p1

    return-object p1
.end method

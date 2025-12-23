.class public final Llyiahf/vczjk/fe2;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $handled:Llyiahf/vczjk/dl7;

.field final synthetic $startEvent:Llyiahf/vczjk/de2;

.field final synthetic this$0:Llyiahf/vczjk/ie2;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/de2;Llyiahf/vczjk/ie2;Llyiahf/vczjk/dl7;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/fe2;->$startEvent:Llyiahf/vczjk/de2;

    iput-object p2, p0, Llyiahf/vczjk/fe2;->this$0:Llyiahf/vczjk/ie2;

    iput-object p3, p0, Llyiahf/vczjk/fe2;->$handled:Llyiahf/vczjk/dl7;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/ie2;

    iget-boolean v0, p1, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-nez v0, :cond_0

    sget-object p1, Llyiahf/vczjk/b0a;->OooOOO:Llyiahf/vczjk/b0a;

    return-object p1

    :cond_0
    iget-object v0, p1, Llyiahf/vczjk/ie2;->OooOoo0:Llyiahf/vczjk/ie2;

    if-nez v0, :cond_1

    goto :goto_0

    :cond_1
    const-string v0, "DragAndDropTarget self reference must be null at the start of a drag and drop session"

    invoke-static {v0}, Llyiahf/vczjk/pz3;->OooO0O0(Ljava/lang/String;)V

    :goto_0
    const/4 v0, 0x0

    iput-object v0, p1, Llyiahf/vczjk/ie2;->OooOoo0:Llyiahf/vczjk/ie2;

    iget-object p1, p0, Llyiahf/vczjk/fe2;->$handled:Llyiahf/vczjk/dl7;

    iget-boolean v0, p1, Llyiahf/vczjk/dl7;->element:Z

    iput-boolean v0, p1, Llyiahf/vczjk/dl7;->element:Z

    sget-object p1, Llyiahf/vczjk/b0a;->OooOOO0:Llyiahf/vczjk/b0a;

    return-object p1
.end method

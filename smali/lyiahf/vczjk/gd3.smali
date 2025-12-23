.class public final Llyiahf/vczjk/gd3;
.super Llyiahf/vczjk/pja;
.source "SourceFile"


# instance fields
.field private final parentContainer:Landroid/view/ViewGroup;


# direct methods
.method public constructor <init>(Landroidx/fragment/app/Oooo0;Landroid/view/ViewGroup;)V
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Attempting to use <fragment> tag to add fragment "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, " to container "

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p0, p1, v0}, Llyiahf/vczjk/pja;-><init>(Landroidx/fragment/app/Oooo0;Ljava/lang/String;)V

    iput-object p2, p0, Llyiahf/vczjk/gd3;->parentContainer:Landroid/view/ViewGroup;

    return-void
.end method
